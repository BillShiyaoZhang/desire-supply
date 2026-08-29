# IAM 当前政策接受与 Consent 授予的 PostgreSQL SELF UoW

> 状态：IAM-01 权威数据库执行设计与 production GREEN。历史阶段先基于动态 catalog head v13取得`17 methods / 33 semantic failures / 0 errors / 0 skips`的有效 RED；现已由 forward-only `0014_expand__policy_consent_self_uow.sql`、真实 `iam_app` psycopg UoW与原17项加一项receipt metadata drift护栏完成GREEN。当前动态head为v14；目标为`18/18`，排除独立Creator Profile刻意RED后的稳定storage为`126/126`。
>
> 适用 operation：`acceptCurrentPolicies` 与 `grantConsent`。业务语义、关闭 HTTP 输入与 Memory 证据见 [IAM 当前政策接受与 Consent 授予命令](/architecture/iam-policy-consent-commands.md)；共同表、receipt 与基础 RLS 见 [IAM PostgreSQL 首个持久化切片](/architecture/iam-postgresql-implementation.md)。本文只拥有这两个已认证 SELF 写命令的真实 PostgreSQL repository/UoW 边界。

## 1. 目标、完成定义与非目标

本切片把两个 Memory 命令映射成两个固定 PostgreSQL 程序。GREEN 的完成定义同时要求：

1. 只以在线角色 `iam_app`、PostgreSQL 18、显式 `READ COMMITTED` transaction执行；
2. exact receipt claim、当前 Session、User If-Match、stored authority、selector/current policy、PolicyAcceptance 或 ConsentGrant 在一个固定锁序中重验；
3. 业务事实、User version、最小 audit、closed outbox 与 COMPLETED receipt原子提交；
4. 同 key并发收口为一次执行加一次 replay，不同 key以 User/current/active-authority锁收口；
5. 每个逻辑写前可注入确定性故障并证明全图回滚；COMMIT acknowledgment丢失只返回 outcome unknown并永久丢弃 physical connection；
6. raw Idempotency-Key、cookie、CSRF、Session handle、正文、内部 recipient与任何 secret sentinel不进入数据库边界、异常、trace、receipt、audit 或 outbox。

本页不实现 HTTP presenter、Session cookie认证、领域 Memory fallback、broker同步发送、Consent撤回或新 scope。fixture可由管理连接建立合法事实，但被测 production路径不得使用 owner、`iam_onboarding`、`iam_system`、BYPASSRLS、临时 GRANT、关闭 trigger或 test-mode SQL。

## 2. v13 schema gap 与 v14 forward-only 实现

有效RED建立时的v13 schema已经具有 receipt、append-only PolicyAcceptance、ConsentGrant、`NULLS NOT DISTINCT` active-authority unique、audit/outbox与基础 SELF read policy，但还不足以实现本命令：

- `iam_app` 没有 User `aggregate_version/updated_at` UPDATE、PolicyAcceptance INSERT、ConsentGrant INSERT/expiry UPDATE或grant category INSERT权限；
- `iam_app` 对 Session只可见普通 DTO 列，不可读取持久 `auth_transaction_id/auth_time/acr/amr` evidence；
- 当前 SELF policy graph是读取投影，不提供可证明无 phantom 的 exact row locks；policy relation上的 `SELECT ... FOR UPDATE/SHARE` 还需要 UPDATE权限，不能通过授予表级 UPDATE来绕过；
- receipt尚无这两个命令重放所需的关闭 `response_http_status`、`response_schema_name`、`response_entity_tag` 与 `current_user_entity_tag`，不得把 transport metadata塞进业务 DTO或自由 `reconstruction_metadata`；
- 既有 SELF RLS operation名与命令写入 predicate尚未为本页两个operation关闭。

这些缺口没有通过改写v0–v13、owner连接、BYPASSRLS或Memory fallback绕过。GREEN只追加v14：增加第5节exact lock function、窄列权限/RLS及两个命令的固定SQL生产UoW，并原子更新受检manifest与review pin。管理fixture只建立合法前置事实，不计作production证据。

## 3. 固定在线身份、pool 与 transaction

两个operation共用独立的 `iam_app` writer pool；它不能与 migration、onboarding、session-authenticator或read-only pool混用。每次 checkout 必须先证明：

- physical connection为IDLE且由pool以 `autocommit=true` 交付；
- `session_user=current_user='iam_app'`，该role为 LOGIN、非owner、`NOSUPERUSER NOBYPASSRLS NOINHERIT`；禁止在请求内 `SET ROLE`；
- `server_version_num` major恰为18，startup compatibility与receipt retained-key readiness已经通过；
- connection上没有未复位 transaction、prepared statement、temporary object、session-level `app.*` 或自定义 search path。

执行固定顺序：

```text
checkout → RESET ROLE → RESET ALL → DISCARD TEMP
→ BEGIN ISOLATION LEVEL READ COMMITTED
→ SET LOCAL TIME ZONE 'UTC' + timeout + exact app.*
→ receipt claim/replay + locked business program
→ state := COMMIT_SENT → COMMIT
→ RESET ROLE → RESET ALL → DISCARD TEMP → closed readback → release
```

`lock_timeout=2s`、`statement_timeout=10s`、`idle_in_transaction_session_timeout=15s` 是首版上限；pre-COMMIT仅对登记的`40001/40P01/55P03`且尚未产生外调的整事务最多重试3次。retry必须重用 command/receipt/evidence/event ID、server command time和payload material，并取得新的physical connection或经过完整reset的IDLE connection。未知SQLSTATE、constraint、row count或编程异常原样暴露给application测试，不能被catch-all伪装成503。

## 4. transaction-local SELF context

GUC只通过参数化 `pg_catalog.set_config(name,value,true)` 安装，并逐项readback；值不拼接到SQL。两operation共同关闭allowlist为：

| GUC | 值 |
| --- | --- |
| `app.scope_kind` | `SELF` |
| `app.operation` | `ACCEPT_CURRENT_POLICIES` 或 `GRANT_CONSENT` |
| `app.actor_user_id` / `app.target_user_id` | exact actor User，二者相同 |
| `app.session_id` / `app.session_family_id` / `app.auth_transaction_id` | 请求中opaque IDs；锁内从持久关系复核 |
| `app.command_id` | receipt ID；也是audit/outbox causation ID |
| `app.command_name` / `app.command_version` | exact `AcceptCurrentPolicies|GrantConsent` / `1` |
| `app.idempotency_key_digest_key_id` / `app.idempotency_key_digest` | 当前claim候选的非秘密key ID与32-byte digest hex |
| `app.policy_selector_digest` / `app.policy_bundle_id` | exact requirement selector与客户端candidate bundle |
| `app.organization_id` | USER_ROLE为空；ORGANIZATION_ROLE为exact scope ID |
| `app.authority_scope_type` / `app.authority_scope_id` | exact关闭requirement reference |

未列出的高风险上下文必须先设置为空并确认，不继承上一请求。raw Idempotency-Key、Cookie、CSRF、handle、document body、recipient ref、contact与subject永远不是GUC。RLS仍是repository guard之外的第二道边界，不把客户端GUC当授权事实；第5节函数必须从已锁持久row复算authority。

## 5. 唯一政策图锁接口

v14提供且只提供一个窄函数：

```text
iam.lock_policy_consent_self_v1(
  actor_user_id uuid,
  session_id uuid,
  selector_digest bytea,
  authority_scope_type text,
  authority_scope_id uuid,
  presented_bundle_id uuid,
  operation text
)
```

函数固定为 `SECURITY DEFINER`、owner=`schema_owner`、`VOLATILE`、`PARALLEL UNSAFE`、`search_path=pg_catalog,iam`、无dynamic SQL；PUBLIC全部撤销，exact signature只授予`iam_app`。入口先要求`session_user='iam_app'`并逐字核对第4节transaction-local上下文，错一项在取得其他主体锁前以固定SQLSTATE/constraint拒绝。为了使FORCE RLS下的owner也只能看exact闭包，migration只增加要求`session_user='iam_app'`、exact operation/context的`schema_owner FOR ALL` lock policies；不向`iam_app`授予policy表UPDATE，也不开放函数给owner login、PUBLIC或其他runtime role。

函数返回一行关闭事实，至少包括：

- SessionFamily/Session/User状态、generation、User version、auth transaction、auth time、acr与canonical amr；
- USER_ROLE或ORGANIZATION_ROLE唯一authority、source ACCEPTED Invitation、role/purpose/stored selector与Organization/Membership状态；
- selector canonical facts/current pointer、current bundle状态/effective window；
- 按position稳定排序的全部bundle document membership、document ID/hash/status/kind/legal effect；
- 按 `(purpose,scope_type,offer_id)` 与category position排序的全部ConsentOffer事实，包括scope derivation、内部recipient、expiry rule/not-after、canonical offer hash；
- actor对current required documents的exact prior PolicyAcceptance evidence；source bundle可为合法SUPERSEDED历史bundle；
- Grant时exact `(user,PILOT_RESEARCH,PLATFORM_PARTICIPATION,NULL)` active-authority row与ordered categories。

函数不得返回policy正文、release signature/manifest、Session handle/CSRF、contact/subject、raw receipt material。selector/current缺失、重复、错绑、future/expired、document/offer parent闭包损坏以登记constraint返回configuration unavailable；健康locked current与presented bundle不同返回足够的safe current ID供`POLICY_BUNDLE_CHANGED`，不能把stale candidate误分类为数据库损坏。

## 6. receipt retained keys、claim 与 replay

原始 Idempotency-Key只存在于HTTP/application最短作用域。进入repository的是：按key ID排序的全部retained identity HMAC candidates、按 `(payload_key_id,canonicalization_version)` 排序的payload HMAC candidates、active IDs与固定 `restricted-canonical-json-v1`。两个HMAC key domains必须不同；request/dataclass/异常的`repr`隐藏digest bytes。

transaction外可用短只读SELF事务读取唯一receipt key-policy row并做exact candidate lookup；零行进入写UoW，一行按row保存的key/canonicalizer选择prepared candidate，多行使writer unhealthy。写UoW中唯一合法claim仍是：

1. 用active identity digest插入IN_PROGRESS，`ON CONFLICT DO NOTHING RETURNING id`；
2. insert零行时按完整 `(USER,actor,command,version,key_id,digest)` `FOR UPDATE`；unique等待竞争transaction结束；
3. replay row必须恰为COMPLETED、target=`User/actor`、method=`POST`、canonical path恰为 `/v1/me/policy-acceptances` 或 `/v1/me/consents`、If-Match/payload HMAC/closed response metadata逐字一致；same payload继续第7节Session/User principal锁后replay，different payload返回`IDEMPOTENCY_KEY_REUSED`；
4. insert成功者才可执行业务图；最终同事务把receipt改为COMPLETED。任何退出都回滚IN_PROGRESS，不存在可见pending或`COMMAND_IN_PROGRESS`分支。

completed exact replay仍必须验证受控SessionFamily/Session/User属于principal且当前有效，但跳过authority/current bundle/历史evidence重验，不重复audit/outbox，也不产生Cookie。v14已增加关闭的`response_http_status`、`response_schema_name`、`response_entity_tag`与`current_user_entity_tag`：IN_PROGRESS四列全NULL；Accept completed固定`200/PolicyRequirementStatusDto`且两个User ETag相同；Grant固定`201/ConsentGrantDto`、grant ETag绑定body aggregate version并独立保存current User ETag。`safe_response_body`只存OpenAPI DTO，`reconstruction_metadata`继续为NULL。replay逐字读取并绑定这些持久值，不能从DTO或当前User version静默重建；缺retained key/canonicalizer、损坏row shape、metadata drift或unknown response schema均fail closed 503。

## 7. 全局固定锁序

同一transaction内锁序不可按operation自由重排：

```text
1 exact receipt identity
2 SessionFamily → Session → User
3 Organization? → Membership?
4 exact UserRoleGrant | MembershipRoleGrant → source AccessInvitation
5 PolicySelector → current PolicyBundle
6 bundle parent → PolicyBundleDocument/PolicyDocument by position then UUID
7 ConsentOffer by authority key then UUID → categories by position
8 existing PolicyAcceptance by document position then UUID
9 exact Consent active-authority key (Grant only; NULL scope uses IS NOT DISTINCT FROM)
10 writes in section 10 order
```

父bundle lock在child查询前取得并一直持有，防止phantom membership/offer。多个UUID按raw UUID byte order，position先于UUID；不得依赖heap、index或request顺序。same key竞争首先在receipt unique等待并replay；different key同User在Family/User lock串行。第一命令改变User version后，第二命令用旧If-Match返回`PRECONDITION_FAILED`并回滚自己的receipt。不同User但同global consent authority并不冲突，因为authority key包含User。

## 8. Session、User、authority 与 current race

receipt取得后，函数锁并逐字段复核：Family与Session ACTIVE、exact current generation、同actor、两个exclusive deadline未到；Session引用成功AuthTransaction且evidence shape完整；User ACTIVE且version等于If-Match。User stale必须在政策或consent写前返回412。

authority reference不从bundle反推：

- `USER_ROLE/null`只能匹配actor的exact active CREATOR grant及其ACCEPTED source Invitation；
- `ORGANIZATION_ROLE/id`只能匹配exact ACTIVE Organization、ACTIVE Membership与active role grant，所有actor/org/source/selector/role字段闭合。

不存在或不属于actor统一404；同reference重复、orphan、source错绑或持久闭包损坏503。锁selector/current后再次与客户端bundle比较：健康current发生变化是409 `POLICY_BUNDLE_CHANGED`；缺current、错selector、非ACTIVE或不在effective window是503。测试的current race必须由另一个已提交transaction改变pointer，不能被被测UoW rollback一并恢复。

## 9. PolicyAcceptance 与 ConsentGrant

`AcceptCurrentPolicies`对current required documents按bundle position验证请求exact set。既有evidence identity唯一为 `(user_id,document_id,content_sha256)`；row的`bundle_id`只是首次source audit。复用旧source evidence时必须同时验证owner、immutable document/hash/legal effect、历史source bundle membership和完整Session evidence；不要求source bundle等于current，不更新时间、不发第二个事件。缺少的row按position插入并记录current bundle；同document不同hash或损坏source不能复制覆盖。

`GrantConsent`先用同一规则证明所有current required evidence存在，再只接受发布的generic PILOT offer。offer canonical bytes在adapter用唯一`consent-offer-json-v1`独立复算并constant-compare。ACTIVE authority使用数据库既有唯一键：

```sql
(user_id, purpose, scope_type, scope_id) NULLS NOT DISTINCT
WHERE status = 'ACTIVE'
```

exact authority先`FOR UPDATE`。`expires_at <= transaction_timestamp()`时按ID/version/status/deadline CAS物化EXPIRED；expiry不是read-time猜测，必须与本命令其他写一起提交或回滚。仍有效row只在offer/version/bundle、ordered categories、recipient/document/hash、原granted_at派生expiry及Session evidence逐字一致时复用；不同事实返回`INVALID_STATE_TRANSITION`。无active row使用partial-index predicate的`INSERT ... ON CONFLICT DO NOTHING RETURNING`，零行后等待并重读，收口为exact reuse或conflict；禁止捕获unique violation后在aborted transaction继续。

## 10. 逻辑写顺序与 checkpoint

production fault port只可在每个statement前观察 `(closed checkpoint, contiguous ordinal)`，不能改SQL/参数、跳过或提交。实际变化取下列子集：

```text
command_receipt.claim
policy_acceptance.insert[*]                       # Accept
consent_grant.expire[*]                           # Grant
consent_grant.insert                              # Grant if no exact live row
consent_grant_category.insert[*]                  # derived ordered categories
user.version-cas                                  # only when authorization effect changes
audit_event.insert
outbox_event.insert[*]
command_receipt.complete
```

Accept真正新增evidence时每document一条`PolicyAccepted`，并恰一条`PolicyRequirementsSatisfied`；全reuse无event/User increment。Grant新建时恰一条`ConsentGranted`；exact reuse无event/User increment。User CAS必须使用锁定before version并要求affected row恰为1。audit总是一条，result关闭为CREATED或REUSED。所有outbox insert前用正式IAM v1 envelope/payload schema验证，delivery字段初始化为PENDING/0；transaction内不调用broker。

任一checkpoint抛错必须显式ROLLBACK，且User、evidence、expiry projection、receipt、audit、outbox before/after逐项相等；不能只断言异常。确认rollback并成功reset、IDLE readback后才能release，否则discard。

## 11. audit、outbox 与 secret boundary

AuditEvent action固定 `POLICY_ACCEPT` 或 `CONSENT_GRANT`，只含actor/original actor、User target、适用Organization、持久authority派生role/purpose、auth strength code、before/after User version、CREATED/REUSED、command/correlation/causation/trace。`safe_attributes`首版为空关闭对象；不得保存request body、selector/hash、document/offer正文、categories、recipient ref、receipt digest、Session/AuthTransaction evidence或自由文本。

outbox严格使用已发布`iam-v1.schema.json`：`PolicyAccepted`、`PolicyRequirementsSatisfied`、`ConsentGranted` envelope/payload无未知字段。内部recipient、canonical offer、raw签名/manifest、receipt、Session证据都不进入event。数据库只保存业务必需的ConsentGrant internal recipient；它仍不得进入普通DTO、audit/outbox/trace。

测试使用显眼raw Idempotency-Key、Session handle、CSRF、contact、subject、policy body与recipient sentinel，但只把digest/opaque ID交给adapter。递归隐私扫描覆盖request/exception/trace、receipt/audit/outbox以及允许检查的IAM text/json/bytea列；不得开启bind logging或把request repr写进失败消息。

## 12. COMMIT_SENT、discard 与 recovery

adapter在调用driver `COMMIT`前原子切换`WRITING → COMMIT_SENT`。此后任何driver/连接/timeout异常只产生`PolicyConsentPostgresCommitOutcomeUnknownError(code='COMMAND_OUTCOME_UNKNOWN')`：

- 不ROLLBACK、RESET、release或查询receipt；
- 只调用一次`connection_source.discard(physical_connection)`；
- 同一request内不retry、不猜测server是否提交。

真实PG18 ack-loss wrapper先让server处理COMMIT，再立即关闭socket并抛`OperationalError`。测试证明旧backend被discard且没有COMMIT后的SQL；调用方以same key在新backend重试，若server已提交则验证Session principal后replay，若未提交才重新claim。两种路径都不能依赖进程内缓存。

pre-COMMIT异常在同一connection显式ROLLBACK；只有transaction status IDLE、`RESET ROLE/ALL`、`DISCARD TEMP`与关闭GUC readback成功才release。reset失败、错误role、非IDLE checkout或未知server major一律discard并fail closed。pool测试必须连续复用同一physical connection执行不同actor/operation，证明第二请求看不到第一请求任何`app.*`。

## 13. 真实 PostgreSQL 18 RED 矩阵

新测试每个method从`MigrationCatalog.load()`动态读取当前head并在临时PostgreSQL 18应用全部受检artifact；不硬编码v13、任何未来migration编号或manifest pin。fixture必须在调用production seam前成功commit并通过CHECK/FK/deferred trigger。测试不skip；migration、fixture、psycopg、SQL、ImportError或编程错误都是error，不是合法RED。

| 测试组 | 必须证明 |
| --- | --- |
| happy | Organization requirement Accept与creator requirement Grant各自完整receipt/User/evidence/audit/outbox事实 |
| acceptance reuse | current bundle复用SUPERSEDED old-source exact acceptance，不重复row/event |
| consent lifecycle | exact ACTIVE reuse；deadline等号物化EXPIRED后新建；同authority不同offer/facts冲突全回滚 |
| concurrency | same key双真实连接只执行一次并replay；different keys在User/authority锁后stale或exact reuse，无双效果 |
| concurrency guards | stale If-Match零写；外部已提交current pointer race返回bundle changed且外部变化保留 |
| atomicity | 第10节每个实际checkpoint/ordinal故障后全图snapshot相等，无可见IN_PROGRESS receipt |
| commit boundary | server已处理COMMIT后ack-loss只unknown+discard；same key新backend恢复 |
| role/RLS/pool | exact `iam_app`、非owner/no BYPASS、FORCE RLS、无context零行或42501、跨请求GUC清零 |
| privacy | raw sentinels不在request repr、异常、SQL trace、receipt/audit/outbox或非必要IAM投影 |

default-deny阶段测试helper只窄捕获`PolicyConsentPostgresBehaviorNotAvailable`且核对exact sentinel；所有业务差异必须仅由该sentinel导致，错误与skip均为0。进入GREEN时没有放宽业务结果、错误码、写点、rollback、receipt、event或privacy oracle。仅修正了TDD阶段本身互相矛盾的fixture contract：default-deny结构guard改用合法最小成功入口但保留frozen/closed/role/secret断言；privacy Grant场景补入正式required PolicyAcceptance；两个Accept replacement场景统一使用exact Organization authority，replacement helper复用previous document locale，禁止把USER_ROLE selector与ORGANIZATION_ROLE request拼接。这些是fixture前置事实修正，不是production行为放宽。

## 14. 追踪与分期

| ID | 设计保证 | 当前状态 |
| --- | --- | --- |
| `DES-POLICY-CMD-PG-001` | exact SELF role/context、fixed lock graph、old-source acceptance reuse与User If-Match | v14 production + 真实PG18 GREEN |
| `DES-CONSENT-CMD-PG-001` | NULLS NOT DISTINCT authority、expiry materialization、reuse/conflict并发 | v14 production + 真实PG18 GREEN |
| `DES-POLICY-CMD-PG-002` | retained-key receipt、atomic audit/outbox、COMMIT_SENT discard/recovery | v14 production + 真实PG18 GREEN |
| `DES-POLICY-CMD-PG-003` | pool reset、FORCE RLS、secret-safe request/trace/database boundary | v14 production + 真实PG18 GREEN |

实施顺序已完成到：本文设计 → immutable/default-deny seam → 真实PG18语义RED → v14 forward-only migration → fixed SQL最小GREEN → 稳定平台回归。HTTP composition/E2E仍是显式后续；真实数据库GREEN不等于transport或部署装配已完成。

## 15. 2026-08-08 有效 RED 证据

RED阶段的production文件为`platform/src/desire_platform/identity_access/adapters/postgres/policy_consent_commands.py`；当时它关闭了`iam_app`设置、两个operation、retained receipt digest material、execution scope、generated IDs、write checkpoint、connection disposition与COMMIT unknown类型，但两个公开执行方法都只抛exact `IAM_POSTGRES_POLICY_CONSENT_BEHAVIOR_NOT_AVAILABLE`。测试文件为`platform/tests/storage/postgres/test_policy_consent_commands_uow_red.py`，每个method都从`MigrationCatalog.load()`动态取得最终head并在临时PostgreSQL 18安装全部artifact；没有写死v13、migration checksum或manifest pin。

执行：

```bash
cd platform
PYTHONPYCACHEPREFIX=/private/tmp/desire-policy-consent-pg-red-pyc \
PYTHONPATH=src:tests .venv/bin/python -m unittest \
  storage.postgres.test_policy_consent_commands_uow_red -v
```

结果为`Ran 17 tests in 4.835s`、`33 failures`、`0 errors`、`0 skips`。一个immutable/default-deny contract method通过；33个差异都可追到exact sentinel与目标业务结果不相等：两个happy、old-source acceptance reuse、ACTIVE grant exact reuse/expiry/conflict、same/different key真实线程竞争、same-key payload conflict、stale If-Match/current race、17个Accept/Grant实际write checkpoint/ordinal、COMMIT ack-loss的unknown与新backend replay、retained row key replay、`iam_app` pool program/reset、secret-safe成功结果。migration、fixture、deferred trigger、SQL、ImportError、dependency与thread harness均未成为RED原因。

测试已独立证明动态head compatibility row、合法User/Session/creator+Organization authority/current policy fixture、online `iam_app`非super/nonowner/NOBYPASS/NOINHERIT、七张目标表FORCE RLS、无context零行、request/digest `repr`隐藏及raw carrier不进入数据库。它仍不证明任何production业务SQL可用；只有后续保持这33项期望不变完成forward migration和adapter GREEN后，追踪状态才可更新。

## 16. 2026-08-08 RED → GREEN 证据

production保持同一immutable request与operation-specific公开方法，实现PostgreSQL 18 `READ COMMITTED`事务、参数化transaction-local SELF context、retained keyed receipt claim/replay、固定锁图、PolicyAcceptance/ConsentGrant事实、User CAS、audit/outbox、COMMIT_SENT discard/recovery与pool reset。`0014_expand__policy_consent_self_uow.sql`只在稳定v13之后forward-add；v0–v13 bytes不变。最终受检值为：

- v14 SQL raw SHA-256：`79e6642f7f8200787cae7d7f73252b7fe732feb931604d65e3464cd2cf55481d`；
- canonical manifest raw SHA-256 / review pin：`1b8093c4d70fa1c26ac98904b61bebe438a3fb09c2d418a4f8505fe359a66884`；
- catalog head：`14`。

目标执行：

```bash
cd platform
PYTHONPYCACHEPREFIX=/private/tmp/desire-policy-consent-receipt-pyc \
PYTHONPATH=src:tests .venv/bin/python -m unittest \
  storage.postgres.test_policy_consent_commands_uow_red -q
```

结果为`Ran 18 tests in 11.852s — OK`。原17个method的业务结果、错误码、write checkpoint/ordinal、rollback snapshot、并发、ack-loss、retained key、RLS/pool与secret断言保持；第18项直接持久化shape-valid但与locked User漂移的completed ETag，证明replay返回503且不从DTO/User version重算。合法retained-key replay同时断言SQL读取四个metadata列并返回持久ETag。v14数据库CHECK把两个命令的IN_PROGRESS/COMPLETED、HTTP status、schema name、path和ETag形状关闭；其他历史command receipt不被追溯要求新列。

稳定storage回归明确排除并发新增、由另一切片拥有的`test_creator_profile_postgres_red.py`：其34个default-deny semantic failures、0 errors是有效刻意RED，不是v14回归。其余全部storage模块结果为`Ran 126 tests in 41.060s — OK`。同轮非storage回归为policy/consent Memory `15/15`、Accept Memory `49/49`、当前全contract目录`59/59`。真实HTTP presenter/composition、部署pool wiring与端到端server仍未由本证据完成。
