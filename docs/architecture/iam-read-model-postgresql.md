# IAM read model 的 PostgreSQL 18 fixed-query 与 RLS 设计

> 状态：`TEST-DB-IAM-READ-001` 已按 RED → GREEN 完成；九个 production fixed-query read programs、在线角色/RLS、连接复位和真实 PostgreSQL 18 证据均已落地。
>
> 基线：设计/RED最初针对受检`0009`完成；并发修复占用`0010`，PolicyAcceptance复用占用最终`0011`（SQL SHA-256 `21c71f56e369d6e88b1ed209a435b34f6bca9cdca60a5a4795ad3e28f43ead9e`）。read-model只追加`0012_expand__iam_read_models.sql`（SQL SHA-256 `58328e2578ecb04718ad0b641c28676f231ee1a2d0e73b735522109d204363ec`），未改写v0–v11 bytes；本切片验收时的canonical manifest/review pin均为`2effd146c730f06dccb2607ad4e32d2d95186d66b87d39e8aed88843c8b1ac7e`，catalog head与app兼容窗口均为12。

本文把 [IAM read model 与 application query 边界](/architecture/iam-read-models.md)的九个 query port 收敛为可评审的 PostgreSQL 18 执行协议。它补充 [IAM PostgreSQL 18 首个持久化切片](/architecture/iam-postgresql-implementation.md)，但不改写后者；状态、DTO、错误、cursor、ETag 与 cache 语义仍由前一页和机器契约拥有。

## 1. 完成定义与禁止路径

生产 repository 只有九个公开方法。每次调用必须满足以下全部条件：

1. 从对应在线角色的独立连接源 checkout 一个 physical connection；`iam_app` 与 `iam_onboarding` 不能共享 pool。
2. 验证 PostgreSQL major 为 18、`current_user=session_user=expected_role`、transaction status 为 IDLE；不执行 `SET ROLE`。
3. 开启一个 `READ ONLY, READ COMMITTED` transaction，以参数化 `set_config(..., true)` 设置关闭的 operation scope。
4. 只执行本文登记的 fixed statements；业务 statement 数不超过 operation budget，结果来自同一 transaction timestamp。
5. 不执行写入、`FOR UPDATE/SHARE`、advisory lock、显式 table lock、temporary object、DDL、dynamic SQL、offset pagination、`COUNT(*)` 或逐 row child query。
6. 完整读取成功后显式 `COMMIT`；任何读取/校验异常先确认 `ROLLBACK`。只把 IDLE、role/scope reset 验证成功的连接 release，否则 discard。
7. repository 只返回 `ReadModelSnapshot` 的关闭 facts；不能返回 psycopg row、cursor、connection、SQL、bind values 或 arbitrary mapping API。

缺实现不能退回 Memory repository、owner connection、BYPASSRLS connection、通用 `SELECT *` 或逐项补查。历史semantic RED sentinel类型仍为测试兼容性保留，但九个production方法均不再发出它；运行时失败只走关闭的configuration/storage error边界。

## 2. 连接、事务与 statement 计数

每次调用的线性协议固定如下：

```text
checkout expected-role connection
  -> verify IDLE / PostgreSQL 18 / exact current_user and session_user
  -> BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY
  -> SET LOCAL lock_timeout / statement_timeout / idle_in_transaction_session_timeout
  -> SET LOCAL closed app.* scope through pg_catalog.set_config(name,value,true)
  -> verify transaction_read_only=true and closed scope echo
  -> execute 1..N registered business statements
  -> validate cardinality / byte and row ceilings
  -> COMMIT
  -> RESET ROLE; RESET ALL; DISCARD TEMP
  -> verify IDLE / exact role / every app.* setting empty
  -> release, otherwise discard
```

`ReadModelSnapshot.statement_count` 只计registry登记的业务statements；`BEGIN`、timeout、`set_config`、scope echo、`COMMIT/ROLLBACK`与reset不计入application budget，但integration trace必须看得到。transaction time在设置UTC之后由关闭context statement中的`transaction_timestamp()`取得，所有业务statements共享该snapshot；不能在Python clock中伪造。

固定部署范围为：

| 设置 | 关闭范围 |
| --- | --- |
| `lock_timeout` | `1..1000 ms`；read path本身不主动取锁，只为意外阻塞设上界 |
| `statement_timeout` | `1..5000 ms` |
| `idle_in_transaction_session_timeout` | `1..10000 ms` |
| 单一 statement rows | `<= 101` page roots；child aggregation有单独关闭上限 |
| 单一 policy document body | `<= 200 KiB UTF-8` |
| 单次 snapshot内部 facts | `<= 2 MiB`；超过即 `SERVICE_UNAVAILABLE` |

只读 transaction没有 COMMIT outcome unknown 的业务副作用，但断链 connection仍必须 discard；repository不在断链后重用同一 physical connection继续查询，也不返回 partial snapshot。幂等读取可由上层发起新调用，adapter本身不隐藏自动 retry。

## 3. Fixed statement registry

statement名字、顺序、role、scope、operation和budget属于版本化代码常量，不是请求输入。首版 registry如下：

| operation | role / scope / operation GUC | 固定 statements（顺序） | budget |
| --- | --- | --- | ---: |
| `getSessionBootstrap` | `iam_app / SELF / READ_SESSION_BOOTSTRAP` | `read_session_bootstrap_v1` | 1 |
| `inspectAccessInvitation` | `iam_onboarding / INVITATION / INSPECT` | `read_invitation_preview_v1` | 1 |
| `getPolicyBundle` | `iam_app / PUBLIC_POLICY_READ / READ_PUBLIC_POLICY_BUNDLE` | `read_public_policy_bundle_v1`; `read_public_policy_documents_v1`; `read_public_policy_offers_v1` | 3 |
| `getMe` | `iam_app / SELF / ME_READ_MODEL` | `read_me_self_summary_v1`; `read_me_authority_policy_graph_v1` | 2 |
| `listMyConsentGrants` | `iam_app / SELF / LIST_MY_CONSENT_GRANTS` | `read_my_consent_grants_page_v1`; `read_my_consent_grant_children_v1` | 2 |
| `listMySessions` | `iam_app / SELF / LIST_MY_SESSIONS` | `read_my_sessions_page_v1` | 1 |
| `getOrganizationSummary` | `iam_app / ORGANIZATION / READ_ORGANIZATION_SUMMARY` | `read_organization_summary_v1` | 1 |
| `listOrganizationAccessInvitations` | `iam_app / ORGANIZATION / LIST_ORGANIZATION_INVITATIONS` | `read_organization_actor_authority_v1`; `read_organization_invitations_page_v1` | 2 |
| `listOrganizationMemberships` | `iam_app / ORGANIZATION / LIST_ORGANIZATION_MEMBERSHIPS` | `read_organization_actor_authority_v1`; `read_organization_memberships_page_v1` | 2 |

每个 statement在模块内是单一 static SQL常量，只使用 `%s` bind parameters。禁止根据 include、sort、status、role、locale、cursor或调用方字段拼 SQL。不同 operation 即使共享SQL片段也有独立 registry identity；未来变更选择列、join、filter、order、aggregate或上限时必须登记新 statement version，并同步 cursor query-shape digest。

## 4. Scope 设置和权威来源

共同认证 scope只接受 middleware 已解析的候选 `actor_user_id` 与 `session_id`，但数据库在同一 snapshot重新验证 User、Session和Family。候选值缩小可见集，不是 authority证明。

| operation族 | 必填 transaction-local GUC | 禁止由caller设置的值 |
| --- | --- | --- |
| SELF exact | `scope_kind,operation,actor_user_id,session_id` | family、generation、role、User status |
| invitation inspect | `scope_kind,operation,target_invitation_id`；nonce/key/format已由上游capability verifier校验，不进入GUC | Organization、selector、bundle、mask、capability secrets |
| public policy | `scope_kind,operation,policy_bundle_id` | selector、status、effective time |
| Organization summary | `scope_kind,operation,actor_user_id,session_id,organization_id` | membership ID/version、role |
| Organization admin pages | 同上 | `actor_membership_id`、`actor_membership_version`、`actor_organization_role` |

v11之前的Organization policy信任三个actor Membership GUC非空，且允许`DEMAND_OWNER`看到Membership/role relations；这不足以证明两个管理列表的ORG_ADMIN authority。`0012`以read-specific RLS和窄SECURITY DEFINER boolean validator从exact actor Session → ACTIVE User → ACTIVE Membership →未撤销role自行验证，不再接收这三个authority GUC。summary允许`ORG_ADMIN | DEMAND_OWNER`；两个管理列表只允许`ORG_ADMIN`。

读取用 SECURITY DEFINER 只允许用于无法以不递归 RLS表达的关闭验证/投影；每个函数必须：无caller-controlled SQL、固定`search_path=pg_catalog,iam`、PUBLIC无EXECUTE、exact runtime role有EXECUTE、owner非在线role且仍受FORCE RLS收缩policy。不得新增按任意 User/Organization ID读取的通用函数。

## 5. 九个 SQL shape

### 5.1 Session bootstrap

`read_session_bootstrap_v1` 用 exact actor/session join `users + sessions + session_families`，返回application authority字段和CSRF salt/key/digest；where中复核ACTIVE/current generation及两个exclusive deadline。它不返回handle digest、auth evidence、onboarding binding或其他Session。

v11的`iam_app`对`sessions`没有CSRF三列权限，SELF policy也未绑定operation/exact session。`0012`新增由非在线owner持有、只向exact bootstrap operation开放的projection，没有把CSRF列授予通用SELF列表。

### 5.2 Invitation preview

`read_invitation_preview_v1` 以 exact Invitation为root，在一条statement内返回Invitation capability binding、Organization public name、stored selector/current bundle及完整hash-validation policy graph JSON。没有匹配时是统一unavailable，不区分ID、nonce、终态、expiry或organization状态。

v11存在两个阻断：Invitation表没有`token_format_version`，且`iam_onboarding`的preview列权限不含nonce/key。`0012`增加受constraint与immutable trigger保护的`token_format_version`，并为exact INSPECT projection提供nonce/key/format；列表和safe DTO仍不暴露这些列。既有row只回填发布前唯一受支持格式。

### 5.3 Public policy bundle

三条statement共享exact bundle scope与transaction time：父statement返回selector+bundle；documents按`position,document_id`；offers按`purpose,offer_id`并在同一statement按category position聚合。每个child query再次依赖可见的ACTIVE/effective父bundle，不能只比较caller bundle ID。

v11没有PUBLIC_POLICY_READ selector policy，因而无法独立复算selector digest；`0012`只开放exact bundle所指selector。公开offers fixed statement读取内部hash输入`scope_derivation/recipient_ref/expiry_days`用于进程内复算，但projection DTO删除这些字段，且没有开放relation-wide列权限。

### 5.4 Me

第一条只调用 hardened self summary并校验一行User、多Organization排序与无duplicate；第二条以单个JSON aggregate批量返回UserRoleGrant、MembershipRoleGrant、source Invitation、selector/current policy graph及本人acceptance。PENDING User第二条仍执行并必须返回关闭空集合，避免根据状态产生不透明statement count变化。

v11的policy/offer列权限不足以复算canonical offer hash，且既有`ME_POLICY_REQUIREMENTS`输出不是application所需完整fact graph。`0012`增加exact actor的窄projection；`recipient_ref`只用于内部校验，不进入safe DTO、telemetry或异常。

### 5.5 SELF pages

Consent root statement按`(granted_at DESC,id DESC)`取`limit+1`并同时验证actor authority；第二条只对这批root IDs批量取ordered categories与Withdrawal。它读取内部`recipient_ref`仅做一致性验证。Session statement以一个CTE同时验证current authority并返回保留期内Sessions，按`(created_at DESC,id DESC)`，不能逐Session再查Family。

### 5.6 Organization reads

summary statement在一个query中复核actor和target Organization，只返回allowlist。两个admin page的第一条返回关闭actor authority marker和Organization；第二条分别返回`limit+1` Invitation/current-policy bulk graph或Membership/User/历史role bulk graph。Invitation page只使用持久不可逆mask；不得为满足application Memory sentinel而解密contact locator。application fact已从`contact_locator`比较改成安全布尔证据，该证据只由不投影plaintext locator的fixed statement路径产生。

Membership page的target User只开放`id,display_handle`，不能读取external identity、contact或provider subject。REVOKED Membership可返回其source-bound历史role label；ACTIVE/SUSPENDED只返回未撤销role。

## 6. Keyset cursor 与snapshot

四个page的root SQL模板恰为：

```sql
WHERE created_at <= %(snapshot_at)s
  AND (
      %(after_created_at)s IS NULL
      OR (created_at, id) < (%(after_created_at)s, %(after_id)s)
  )
ORDER BY created_at DESC, id DESC
LIMIT %(limit_plus_one)s
```

首页`snapshot_at`由同一transaction的`transaction_timestamp()`产生；后续页使用已认证cursor中的值，但仍要求`cursor.snapshot_at <= transaction_timestamp()`。`after_id`是canonical UUID并使用PostgreSQL UUID order。禁止text/locale排序、`OFFSET`、总数查询或先取全量后Python分页。

query-shape digest覆盖operation、statement versions、sort tuple、status-retention规则、root/child上限和projection version。当前application与PostgreSQL repository共同导入同一个immutable registry，已移除Memory占位digest。任何shape变化要么保持旧statement直到旧cursor TTL结束，要么发布新cursor version；不能悄悄接受旧digest并改变SQL。

## 7. Hash、orphan与corruption裁决

repository不把数据库constraint存在当作完整性证明。它必须把足够事实交给application独立验证，并在SQL层先拒绝不闭合cardinality：

- selector恰一行、current bundle恰一行且ACTIVE/effective；缺失与重复均是policy corruption；
- document membership位置从1连续、identity唯一、body UTF-8 byte hash可复算；
- offer、supporting CONSENT_TEXT document和ordered categories闭合，canonical hash可复算；
- source Invitation、Membership/role、User/Organization逐字段同scope；不能过滤orphan后返回partial page；
- Withdrawal恰与WITHDRAWN grant一一对应；ACTIVE/EXPIRED不得带withdrawal；
- root/child中出现跨actor或跨Organization row是RLS/adapter故障，不是普通404。

公开exact bundle不存在或inactive返回application可映射的not-found snapshot；已找到root后才发现pointer、child、hash或shape损坏必须成为`POLICY_CONFIGURATION_UNAVAILABLE`。其他scope/cardinality/UTC/order损坏为`SERVICE_UNAVAILABLE`。SQLSTATE、relation、bind值或row正文不进入HTTP错误。

## 8. No-lock/no-write 与运行时检测

static gate对每条registered SQL做token/parser检查，拒绝：

```text
INSERT UPDATE DELETE MERGE COPY CALL DO
CREATE ALTER DROP TRUNCATE GRANT REVOKE
FOR UPDATE FOR NO KEY UPDATE FOR SHARE FOR KEY SHARE
pg_advisory_* LOCK TABLE OFFSET COUNT(*)
```

真实PG测试还要在调用前后读取`pg_stat_xact_*`/目标表快照，并从另一个connection用`pg_locks`确认repository backend没有relation/tuple/advisory heavyweight lock；普通SELECT所需的`AccessShareLock`是PostgreSQL执行必然，允许但不能阻塞writer，测试以并发`ALTER`之外的业务UPDATE在有界时间完成来区分。transaction必须报告`transaction_read_only=on`；任何write尝试应由数据库拒绝，而不是只靠字符串扫描。

## 9. Pool reset 与秘密边界

连接源只有`checkout/release/discard`。成功、已确认rollback和reset成功才release；以下任一情况直接discard：role/server/status错、scope echo多余或缺失、transaction断链、rollback未确认、reset失败、残留prepared cursor/temp object或任意`app.*` setting非空。

reset顺序固定为`RESET ROLE; RESET ALL; DISCARD TEMP`，随后回读role/status和本文列出的全部GUC。固定prepared statements可由psycopg缓存，但不能保存bind值；unexpected named cursor或temporary object会导致discard。测试必须在同一physical connection先执行actor A，再执行actor B/anonymous，证明B不能看到A的User、Organization、Session、Invitation、cursor boundary或policy scope。

以下sentinel不得出现在repository/request/snapshot/exception/trace的普通repr，或数据库text/json/bytea投影之外的诊断：raw Session handle、raw invitation token、raw cursor、contact locator、provider subject、CSRF材料、handle digest、recipient ref、policy signature及SQL binds。CSRF salt/digest和recipient ref可存在于关闭internal snapshot，但对应dataclass/facts repr必须隐藏；safe response与telemetry仍不得含它们。

## 10. v11阻断与forward-only `0012`结果

`0012`只forward-add/replace policy、projection、function、column/constraint和精确grant，没有改写v0–v11 raw bytes：

| 差距 | v11阻断 | `0012`结果 |
| --- | --- | --- |
| Session bootstrap | `iam_app`无CSRF列，SELF不是exact operation | owner-enforced exact bootstrap view/policy |
| Invitation capability | 无format列，INSPECT无nonce/key列 | immutable format列、constraint/trigger与exact projection |
| public selector/hash | PUBLIC scope看不到selector；offer hash内部列不可读 | exact bundle selector/offer validation policies |
| `/me`完整graph | summary与policy facts分裂，内部hash输入不足 | bounded exact-actor graph statements |
| Consent page | `recipient_ref`不可用于一致性验证 | exact SELF internal projection |
| Organization authority | RLS信任caller-derived membership/role GUC | fixed-search-path same-snapshot boolean validator；PUBLIC无EXECUTE |
| Organization invitations | `iam_app`没有Organization invitation list policy/columns | ORG_ADMIN-only page policy/projection |
| Organization memberships | DEMAND_OWNER可见relation；target User不可见 | ORG_ADMIN-only projection与User allowlist |
| mask validation | application fake要求plaintext locator | issue-time verified boolean evidence，不解密locator |
| cursor digest | application使用Memory占位digest | application/adapter共享immutable registry constant |

迁移catalog同时固定四个read views、online-role ACL/security属性与RLS assertion surface。migration runner的schema head、min app和max app兼容版本从canonical catalog head动态派生；head 12数据库中的compatibility tuple为`('iam', 12, 12, 12, 12)`，不会因后续forward migration遗留手工版本常量。

## 11. TDD证据与发布门禁

实际顺序与结果如下：

1. 先落本文、shared registry、production default-deny repository surface和真实PostgreSQL fixture，不登记read migration。
2. `TEST-DB-IAM-READ-001`取得有效semantic RED：9个test methods，35 failures、0 errors、0 skips；失败来自缺少fixed-query/RLS行为及明确的v11 schema阻断。
3. 在稳定`0011`之后只追加受检`0012`，再实现九个fixed SQL programs和关闭connection protocol。
4. 真实PostgreSQL 18 GREEN为9/9：九项happy snapshot、跨User/Organization/anonymous bundle、status/orphan/hash drift、statement budget/read-only/no-lock/no-write、四种pagination、同PID pool reset和secret sentinel全部通过。
5. 回归证据：application read与contract 33/33、catalog/artifact 13/13、migration runner 17/17、真实migration dependency 4/4、完整storage 106/106均通过；既有独立storage 68/68也在head 12复验通过。全部为0 failures、0 errors、0 skips。

已满足的发布门禁：

- 九个handler成功DTO与Memory oracle一致，且错误分类/不披露一致；
- statement trace逐项等于registry，所有transaction只读且无业务锁/写；
- online role非owner、无BYPASSRLS，跨scope direct/join/keyset均零行或42501；
- current pointer、orphan和hash drift不回退旧bundle或partial row；
- cursor snapshot与四种第二页稳定；
- 同physical connection的scope/reset测试通过；
- raw秘密递归扫描为零命中；
- migration、application、contracts和既有storage保持GREEN。

后续若改变selection、join、order、retention、projection或cursor shape，必须追加新statement/migration版本并重复上述真实PostgreSQL门禁；不能原地改写既有migration或复用旧query-shape digest。
