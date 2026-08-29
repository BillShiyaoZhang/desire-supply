# Demand PostgreSQL fixed-UoW、RLS 与 MATCH_INPUT

本文把 [Demand 生命周期设计](/architecture/demand-lifecycle.md) 中尚未落到可实现数据库协议的部分关闭为 PostgreSQL 18 设计。它只覆盖 Demand Context 拥有的 root、不可变 version、submission、review assignment/review、funding marker、matching request、source inbox 与 command receipt，以及写入共享 audit/outbox 的窄能力；不把 IAM、Funding、MatchingAttempt、Invitation、Selection 或 Project 的所有权搬进 Demand。

本文是 Demand PostgreSQL catalog、adapter 和真实数据库测试的权威实现输入。通用 IAM PostgreSQL 约束继续由 [ADR-0004](/decisions/0004-iam-onboarding-persistence-and-postgres.md) 与 [IAM PostgreSQL 实现](/architecture/iam-postgresql-implementation.md) 管辖；两者冲突时，跨 Context 认证事实以 IAM 的关闭 capability 为准，Demand 业务事实以本文为准。

## 1. 当前切片、非目标与发布门槛

本切片先发布三件事：

1. 独立、可导航的数据库设计；
2. production 可导入、深度不可变、默认拒绝的 fixed-program seam；
3. 动态应用最终 IAM catalog 后，在真实 PostgreSQL 18 上运行的语义 RED。

本轮不登记 Demand migration，不修改 IAM migration/manifest/runner，不创建假表，不通过 owner/BYPASSRLS 或 Memory fallback 伪造 GREEN。Demand schema、角色、SQL program、RLS 和持久化行为只有在后续 forward-only Demand catalog 通过真实 PostgreSQL 测试后才能宣称可用。

本设计也不实现 HTTP presenter、生产 composition、真实连接池、Funding provider、Matching worker 或跨服务部署。真实业务内容、预算、资金和候选数据仍受外部启用门槛约束。

## 2. Catalog、schema 与部署依赖

Demand 使用独立 catalog，不能把文件追加到 IAM manifest：

- component 固定为 `demand`；
- migration 根固定为 `desire_platform.demand.adapters.postgres.migrations`；
- manifest 使用受限 canonical JSON、逐文件 raw-byte SHA-256 和独立 reviewed manifest pin；
- compatibility row/view 只表达 Demand 的 current/head，不写入或冒充 IAM compatibility；
- runner 先验证服务器 PostgreSQL 18、IAM catalog 已到部署时动态最终 head，并验证所需 IAM capability version；然后才取得 Demand advisory lock、逐文件事务应用；
- wheel 必须包含 SQL 与 manifest，source tree/wheel catalog bytes完全相同；未知文件、缺文件、checksum漂移、head倒退或 capability缺失一律拒绝。

本设计不把一个并发开发中的 IAM 数字 head 写死。真实测试每次从 `MigrationCatalog.load(...)` 取得最终 catalog并逐项应用，然后验证 ledger与compatibility等于该动态集合。Demand catalog未来用明确的 capability dependency（例如 `iam-demand-owner-authority-v1`），而不是“至少 v14”之类脆弱数字比较。

真实测试先在应用IAM最终catalog后断言IAM没有越界创建`demand` schema；随后仅当独立Demand `manifest.json`存在时，才经公开的`DemandMigrationCatalog`、`DemandMigrationRunner`、`PsycopgDemandMigrationDriver`与三份关闭contract sources动态应用它。当前没有manifest，因此该入口是空的且缺schema保持semantic RED；未来GREEN必须从同一入口加载受评审catalog，不能让online UoW临时建表，也不需要改写17项业务oracle。

schema固定为 `demand`。未来首个 migration至少建立：

- `demand.schema_compatibility`；
- `demand.demands`；
- `demand.demand_versions`；
- `demand.demand_submissions`；
- `demand.demand_review_assignments`；
- `demand.demand_review_assignment_releases`；
- `demand.demand_reviews`；
- `demand.demand_funding_markers`；
- `demand.matching_requests`；
- `demand.source_inbox`；
- `demand.command_receipts`；
- `demand.receipt_key_policy`。

Audit 和 outbox 继续使用共享 `audit.audit_events` 与 `infra.outbox_events`。Demand catalog只能追加精确 Demand RLS policy、检查约束和最小 INSERT/SELECT capability；不能取得共享表 owner，不能放宽 IAM policy，也不能让 Demand role读取其他 bounded context 的行。共享 outbox worker按 event schema registry投递 `demand-v1`，而不是把 Demand payload塞进 `iam-v1`。

## 3. 角色、所有权与连接池

角色关闭为：

| 角色 | LOGIN | BYPASSRLS | 权限 |
| --- | --- | --- | --- |
| `demand_schema_owner` | 否 | 否 | 只拥有 Demand schema对象与Demand专用函数 |
| `demand_migration_runner` | 受控部署连接 | 否 | advisory lock、Demand catalog DDL和必要的共享窄grant |
| `demand_self` | 是，role-bound pool | 否 | owner命令；只能经 exact IAM Organization/DEMAND_OWNER capability访问 |
| `demand_review` | 是，role-bound pool | 否 | exact ACTIVE review assignment 的变更、验证、review-cancel和request-matching |
| `demand_finance` | 是，role-bound pool | 否 | authenticated Funding source event的inbox与最小funding marker写入；不可读取正文 |
| `demand_matching` | 是，role-bound pool | 否 | exact workload + matching request allowlist 的 `MATCH_INPUT` fixed read |
| `demand_system` | 是，role-bound pool | 否 | exact scheduler/source identity 的Expire等关闭系统动作 |

所有在线角色显式 `NOINHERIT`、不是对象owner、无CREATE schema、无任意函数执行权。`PUBLIC` 对 Demand schema、函数、表和sequence均无权限。连接串由 composition按角色分别配置；adapter不接受每请求 role字符串，也不执行 `SET ROLE` 切换业务身份。

每次checkout后先验证 `server_version_num/10000 = 18`、`current_user` 等于该 fixed program的预期在线角色、Demand compatibility等于catalog head，并开始 `READ COMMITTED` 事务。随后只允许：

```text
SET LOCAL TIME ZONE 'UTC'
SET LOCAL lock_timeout = '2000ms'
SET LOCAL statement_timeout = '10000ms'
SET LOCAL idle_in_transaction_session_timeout = '15000ms'
SET LOCAL application_name = '<关闭的低基数字符串>'
SET LOCAL app.actor_kind = '<USER|SYSTEM>'
SET LOCAL app.actor_id = '<uuid>'
SET LOCAL app.session_id = '<uuid或空>'
SET LOCAL app.organization_id = '<uuid>'
SET LOCAL app.operation = '<关闭operation>'
SET LOCAL app.demand_id = '<uuid>'
SET LOCAL app.assignment_id = '<uuid或空>'
SET LOCAL app.source_event_id = '<uuid或空>'
```

GUC只是RLS输入，不是授权证明。任意客户端可伪造GUC，所以RLS/SQL还必须调用受控IAM capability或核对Demand内的assignment/source allowlist。事务结束后执行`ROLLBACK`或确认`COMMIT`，再`RESET ROLE`、`RESET ALL`、`DISCARD TEMP`并复验idle/current role；不执行会破坏psycopg prepared cache的`DEALLOCATE ALL`。配置、reset或role漂移时discard连接；普通已安全回滚的业务拒绝可release。

## 4. IAM authority 的窄投影

Demand在线角色不得直接`SELECT iam.*`。IAM发布一个独立评审、`SECURITY DEFINER`、固定`search_path = pg_catalog, iam, iam_api`的关闭capability。owner路径的逻辑接口固定为：

```text
iam_api.lock_demand_owner_authority_v1(
  actor_user_id uuid,
  session_id uuid,
  organization_id uuid,
  operation text,
  demand_id uuid,
  expected_authority_marker_sha256 bytea
)
```

它是 Demand 生命周期早期草案中 `iam_api.authorize_demand_owner_v1` 的事务锁定后继与唯一 PostgreSQL online 入口：非锁定名称保留为历史设计引用，不与新函数并行授权，也不获得online grant。`operation`只允许`CREATE | CREATE_VERSION | SUBMIT | CANCEL_OWNER`；四个操作的`demand_id`都必须为非零UUID，Create使用application在checkout前已预分配并同时绑定receipt/target的Demand ID，不使用空占位。

`lock_demand_owner_authority_v1`只返回成功行的关闭投影：`actor_user_id, session_id, session_family_id, organization_id, membership_id, membership_role_grant_id, source_invitation_id, policy_selector_digest, current_bundle_id`、它们各自必要的aggregate/generation版本以及`authority_marker_sha256`。返回行本身就证明SessionFamily、Session、User、Organization、Membership均ACTIVE，MembershipRoleGrant未撤销且role=`DEMAND_OWNER`，source Invitation与stored selector/current bundle/current required policy acceptance全部exact；不再返回冗余的status或`marker_matches`布尔值。它不返回联系人、policy正文、consent正文、session handle/CSRF、invitation token或其他组织关系。

marker的canonical UTF-8输入按固定顺序包含capability version、operation、demand ID、所有锁定ID/aggregate version、Session generation、selector digest与current bundle ID/version；然后使用PostgreSQL 18 `sha256(convert_to(...,'UTF8'))`。传入marker不匹配时返回零行，不返回computed marker、差异位置或可用于二次猜测的值。

capability必须按全局顺序锁 IAM Family → Session → User → Organization → Membership → MembershipRoleGrant → selector/current bundle/acceptance marker。Session/组织/关系失效、跨租户、非DEMAND_OWNER、policy不满足、marker漂移或缺事实均返回零行；Demand对外统一non-disclosure，不把“哪一行缺失”暴露为可枚举差异。

reviewer路径使用另一个不引入Organization Membership语义的IAM关闭capability。下列 v1 签名是冻结历史；当前 online 写路径使用 `resolve_demand_reviewer_authority_marker_v2` 与同参数形状的 `lock_demand_reviewer_authority_v2`：

```text
iam_api.lock_demand_reviewer_session_v1(
  actor_user_id uuid,
  session_id uuid,
  organization_id uuid,
  demand_id uuid,
  assignment_id uuid,
  operation text,
  expected_authority_marker_sha256 bytea
)
```

当前 v2 只允许`REQUEST_CHANGES | VERIFY | RELEASE_REVIEW_ASSIGNMENT | REQUEST_MATCHING | CANCEL_REVIEW`，七个参数全部关闭且非空；按Family → Session → User → `OPERATIONS_REVIEWER` duty顺序锁定并验证ACTIVE状态、generation、exclusive idle/absolute deadline、duty版本与有效窗。marker绑定capability version、operation、organization/Demand/assignment ID与全部锁定身份/版本。marker不匹配、cross-user、session/duty失效、`NULL` 或未知 operation 均返回零行。Organization/Demand/assignment只是marker的exact target输入，不会把Organization Membership冒充为review权限；assignment/conflict/expiry仍由Demand本地按锁定顺序验证。

Reviewer仍先经上述关闭IAM session-active capability验证User/Session，但组织归属不能替代review权限。`demand_review`只凭exact ACTIVE `DemandReviewAssignment`、reviewer User、duty grant/version、purpose=`DEMAND_REVIEW`、未过期和冲突attestation进入；reviewer是creator或owner organization成员时拒绝。Funding、matching与system workload分别使用operation-scoped、有限期、绑定source/allowlist的rich attestation；数据库role本身不是workload凭证。

两个capability均为`SECURITY DEFINER`/`VOLATILE`/`PARALLEL UNSAFE`，固定`search_path = pg_catalog, iam, iam_api`，不使用dynamic SQL。`PUBLIC`对schema与函数无权限；owner函数只授`demand_self`，reviewer函数只授`demand_review`，两个角色均不获得直接`SELECT iam.*`。`demand_migration_runner`只获得`infra`与`iam_api`的schema `USAGE`以及`infra.iam_schema_compatibility`的`SELECT`，用于读取动态IAM head并以`to_regprocedure`解析两条冻结签名；它没有两个capability的`EXECUTE`，也没有任何`iam.*`表读取权。Finance/System/Matching的rich workload路径不在IAM 0016中扩张。

IAM capability的新增必须由IAM自己的forward-only catalog拥有；Demand migration只能验证capability存在并向对应Demand role授予被IAM评审的EXECUTE。不存在时整个Demand migration/online call关闭失败。

## 5. 表身份、不可变事实与约束

所有业务主键使用UUID，所有组织拥有表显式保存`organization_id`。子表使用含`organization_id,demand_id`以及必要version ID的复合外键，防止只凭全局UUID跨租户拼接。

### 5.1 Demand root

`demands`保存owner organization、creator User、状态、`aggregate_version`、current/verified/funding/matching指针、client-reference keyed digest、expiry/terminal时间与reason。约束至少包括：

- `(organization_id, client_reference_digest_key_id, client_reference_digest)`唯一；raw client reference不可落库；
- `aggregate_version >= 1`，所有状态转换只经expected-version CAS；
- DRAFT/SUBMITTED/NEEDS_CHANGES不能带verified/funding指针；FUNDED/MATCHING等必须绑定exact current verified version；
- CANCELLED/EXPIRED时间、reason和指针形状关闭；终态不可重新打开；
- root指针只能引用同组织、同Demand子表行。

### 5.2 DemandVersion

`demand_versions`是append-only：`(organization_id,demand_id,version_no)`与version ID唯一；version 1没有based-on，后续version必须指向同Demand的较早version。保存：

- `canonical_version_bytes`（最大1 MiB）；
-解析后的关闭JSONB `content`；
- `content_sha256`；
- `demand_schema_version=1`；
- `canonicalization_version='demand-content-json-v1'`；
- exact taxonomy bundle、creator与UTC时间。

应用写前按published schema验证、独立生成canonical bytes与SHA-256；fixed SQL解析外层关闭字段并校验bytes/JSONB/hash/ID/version/taxonomy一致。应用读取后再次复算。数据库CHECK只证明根类型、长度、digest和跨表身份；没有受信JSON Schema/JCS扩展时不得声称数据库独立证明全部content语义。任何UPDATE/DELETE DemandVersion由trigger拒绝。

### 5.3 Submission、review、funding与matching

- `demand_submissions`按`(organization,demand,demand_version)`唯一，保存exact content hash、content-policy version/result digest和提交者/时间；不能重绑后续version。
- `demand_review_assignments`每个Demand最多一个ACTIVE assignment；assignment含reviewer、duty grant/version、purpose、conflict digest、expires_at和aggregate version。assignment完成/撤销只允许关闭CAS转换。
- `demand_review_assignment_releases` 是 append-only 释放事实，绑定 command ID、assignment、Reviewer、exact submission/version、关闭 `CONFLICT_DECLARED | WORKLOAD_RELEASE` reason 与释放时间；UPDATE/DELETE 由 trigger 拒绝。`CONFLICT_DECLARED` 使同一 Reviewer 不能再次领取同一 submission/version，`WORKLOAD_RELEASE` 不建立该限制。
- `demand_reviews`append-only，绑定exact submission/version/hash/assignment/reviewer；NEEDS_CHANGES必须有非空、唯一、受控reason/field codes，VERIFIED必须没有这两组并保存关闭budget/risk code与evidence summary digest，不保存raw note/evidence。
- `demand_funding_markers`append-only，绑定exact verified version、funding ID、source event/version和amount/currency及provider evidence digest；raw金额、币种组合、provider reference不进入audit/event/log。source event ID唯一。
- `matching_requests`append-only，绑定exact verified version、current funding marker、taxonomy/budget/matching/reason bundle和composite requirement；每个Demand同时最多一个`OPEN`，同一request不能被另一MatchRun改绑。Matching Context通过event协调，不能直接UPDATE Demand root。

## 6. 固定 program 与锁序

production seam发布显式入口，不发布`execute(sql, params)`：

| DB operation | 在线角色 | 主要持久结果 |
| --- | --- | --- |
| `CreateDemand` | `demand_self` | root、version 1、receipt、audit、Created+VersionCreated |
| `CreateDemandVersion` | `demand_self` | immutable version、root CAS、receipt、audit、event |
| `SubmitDemand` | `demand_self` | submission、root CAS、receipt、audit、event |
| `RequestDemandChanges` | `demand_review` | review、assignment complete、root CAS、receipt、audit、event |
| `VerifyDemand` | `demand_review` | review、assignment complete、root CAS、receipt、audit、event |
| `ReleaseDemandReviewAssignment` | `demand_review` | immutable release fact、assignment revoke、root revision、receipt、audit、event |
| `ApplyFundingSecured` | `demand_finance` | source inbox、funding marker、root CAS、audit、event |
| `RequestMatching` | `demand_review` | matching request、root CAS、receipt、audit、event |
| `CancelDemandByOwner` | `demand_self` | root terminal CAS、receipt、audit、event |
| `CancelDemandByReview` | `demand_review` | assignment-bound root terminal CAS、receipt、audit、event |
| `ExpireDemand` | `demand_system` | scheduler inbox、root terminal CAS、audit、event |
| `CaptureDemandMatchInputs` | `demand_matching` | 无写；exact request allowlist的冻结投影 |

`CancelDemand`分成两个数据库program是安全边界，不是两个HTTP operation。应用根据已验证的authority path选择固定factory；数据库不根据客户端可控`assignment_id`在同一连接上切换角色。

每个program有immutable registry：operation、runtime role、prepared statement names、exact statement budget与query-shape SHA-256。未知operation、额外statement、动态标识符、任意filter/order、跨角色program或budget超限均为配置错误。参数化值可以变化，SQL文本和标识符不能变化。

业务事务固定锁序：

1. IAM Family → Session → User → Organization → Membership → MembershipRoleGrant/policy marker；
2. reviewer duty；
3. Demand root → assignment；
4. current DemandVersion；
5. current Submission/Review；
6. current Funding marker；
7. current/open MatchingRequest；
8. source inbox或command receipt claim。

同类ID按UUID byte升序。Create在不存在root时先取得organization+client-reference keyed advisory/unique identity锁；不能稍后逆序补锁。所有事务外policy/hold/rule结果在上述锁完成后逐字段复核root version、version ID、content hash、prospective aggregate version与有效期。

释放命令尤其不得先锁 assignment 再回头锁 IAM 或 Demand root，否则会与领取路径形成反向锁序。它先尝试 exact completed receipt recovery；只有未完成的命令才继续 authority/target discovery。成功保持 Demand 为 `SUBMITTED`、清除 active assignment 投影并递增 root revision，使其他合格 Reviewer 立即看到队列；`CONFLICT_DECLARED` 只对作出声明的 Reviewer 隐藏当前 submission/version。

## 7. Receipt、source inbox 与重放

### 7.1 用户命令receipt

User命令receipt identity固定为：

```text
(principal_kind, principal_id, organization_id,
 command_name, command_version,
 idempotency_key_digest_key_id, idempotency_key_digest)
```

raw Idempotency-Key只在transport/application内存中存在。adapter接收独立keyed identity digest与独立payload HMAC；key IDs不同，canonicalization固定`demand-command-json-v1`。payload覆盖actor/organization、DB operation映射到的公开command identity、path/If-Match、所有关闭body事实、外部证据digest和target，不包含raw key/session/CSRF/content/provider evidence。receipt key policy保存active与仍在retention窗口内的retained key/canonicalizer；缺旧key不能重算或降级，返回SERVICE_UNAVAILABLE。

claim使用唯一索引原子实现：新key写`IN_PROGRESS`，同identity同payload的`COMPLETED`逐字重放，同identity不同payload返回`IDEMPOTENCY_KEY_REUSED`。命中同payload `IN_PROGRESS` 时只允许在固定statement timeout内等待合法竞争事务；等待后仍非完整`COMPLETED`统一返回503 `SERVICE_UNAVAILABLE`且不再执行。v1不发布任何in-progress wire result或新错误码。`COMPLETED`必须保存并逐字读取：HTTP status、response schema name/version、strong ETag、关闭safe response body、target ID/version、event types、completed_at。不能从当前root重算历史响应。字段缺失、未知键、hash/key/canonicalizer不受信或target漂移一律fail closed。

### 7.2 source inbox

Funding与Expire没有客户端Idempotency-Key。它们使用`source_inbox`的关闭身份：`(source_kind,source_event_id,event_type,schema_version,source_aggregate_id,source_aggregate_version,organization_id,demand_id)`，另存authenticated envelope digest。相同source exact replay返回已保存target/version/event结果；同event ID不同事实返回`FUNDING_FACT_CHANGED`或SERVICE_UNAVAILABLE，绝不覆盖。`IN_PROGRESS`与`COMPLETED`的形状和deferred complete-at-commit约束与receipt相同；合法竞争有界等待后仍非COMPLETED也只映射`SERVICE_UNAVAILABLE`，不产生in-progress wire结果。

每个业务事实、receipt/inbox状态、audit和outbox在同一事务。任何logical write checkpoint故障都回滚全部新增/修改；不允许先完成receipt再写event，也不允许在rollback后保留IN_PROGRESS。

## 8. Content policy、SafetyHold 与规则漂移

`SubmitDemand`使用绑定exact version/hash的content-policy ALLOW证据；`SubmitDemand`、`VerifyDemand`和`RequestMatching`使用SafetyHold ALLOW证据。hold关闭字段为actor、organization、demand、prospective aggregate version、demand version、content hash、action、policy version、evaluated/valid-until；任一错绑、过期或BLOCK均零写。

规则requirement绑定taxonomy、budget、risk、matching、reason-code bundles与composite requirement ID及有效窗。Submit/Verify/Matching在事务内锁root/version后重读当前requirement marker：taxonomy或matching规则改变返回已发布的stable conflict，持久事实损坏/registry不可用返回SERVICE_UNAVAILABLE。不能把事务外“ALLOW”当作绕过current race的授权。

## 9. Audit、outbox 与隐私

每个成功状态转换写一条append-only audit和契约规定的最小event。Create必须写两个event，其他当前命令各写一个。outbox envelope在INSERT前由`demand-v1` registry验证，字段/payload exact closed；event不得携带content、预算、币种、data plan、review note、Reviewer/duty身份、provider ref、receipt或secret。`DemandReviewAssignmentReleased` 仅额外携带用于关联被释放租约的 opaque assignment ID 和关闭 reason，不携带 Reviewer 或 authority marker。

Audit只保存action、actor kind/ID、original actor、organization、target、before/after status/version、受控reason、assignment/duty或source credential的最小digest/ID、correlation/causation/trace和结果。不保存content、金额、evidence正文、SQLSTATE或provider错误。

以下值不得出现在repr、异常、SQL文本trace、application_name、日志、metric label、audit、outbox、receipt safe body或dead letter：raw content、预算数值、data handling/model policy、client reference、Idempotency-Key、cookie/CSRF/Session handle、workload credential、review note、funding verification reference和provider token。测试使用唯一sentinel递归扫描所有可观察表面。

## 10. RLS 与 MATCH_INPUT

全部Demand业务表`ENABLE ROW LEVEL SECURITY`并`FORCE ROW LEVEL SECURITY`。Policy按role和operation分开，不能使用一个`app.organization_id`等值policy覆盖所有角色：

- `demand_self`还必须命中exact IAM owner marker，且行organization/demand与operation一致；
- `demand_review`还必须命中ACTIVE assignment、reviewer和duty marker；
- `demand_finance`只可访问source inbox、root最小状态列和funding marker写入路径，正文列不可授权；
- `demand_system`只可访问一个绑定source/operation的target；
- `demand_matching`只能调用`capture_demand_match_inputs_v1`，不能直接SELECT表；
- schema owner也受FORCE RLS，migration验证通过专用受控路径完成，不在online连接禁用RLS。

MATCH_INPUT request固定包含match run、workload principal、已排序且去重的matching request ID allowlist、authorization digest和UTC requested_at，最多500项。fixed function逐项验证OPEN request、exact organization/demand/version/funding/rule bundle仍一致，并在一个只读事务中复算content hash。结果不是“若干ID/hash”的假投影；每项使用深度不可变、整体`repr`隐藏的`DemandPostgresMatchInputSnapshot`，身份面恰为：

```text
matching_request_id / matching_request_version / matching_request_status=OPEN
organization_id / demand_id / demand_status=MATCHING
demand_version_id / demand_version_no / verification_decision=VERIFIED
content_sha256 / taxonomy_bundle_id
funding_id / funding_status=SECURED
composite_rule_requirement_id / budget_rule_bundle_id / risk_rule_bundle_id
matching_rule_bundle_id / reason_code_bundle_id
matching_selector_digest / rule_requirement_sha256
captured_at
```

snapshot另含仅供受限Matching hard-filter/score input使用的关闭值面：`problem_type_codes/domain_codes/task_codes`、`must_have_skills/nice_to_have_skills`、`start_date/due_date/required_weekly_hours/required_duration_weeks`、`currency/minimum_amount_minor/maximum_amount_minor`、`allowed_region_codes/required_language_codes/required_work_mode_code`、`data_sensitivity_code/ai_use_code/budget_override_code`。skill恰为`(skill_code,minimum_level)`且level固定`FOUNDATION=1 / WORKING=2 / ADVANCED=3 / EXPERT=4`；集合按UTF-8 bytes去重排序。语言、工作方式和地域由exact taxonomy bundle下的关闭派生规则变为`LANGUAGE.<upper BCP47>`、`WORK_MODE.<code>`、`REGION.<code>`；不存在node/crosswalk时整批503，不能原样混入小写tag或猜测fallback。AI恰派生为`PROHIBITED | OPTIONAL | REQUIRED`。预算只允许offered minimum/maximum/currency，`direct_cost`、内部预算依据和私密floor不返回；风险只允许算法明确需要的`data_sensitivity_code`与已审核`budget_override_code`，不返回uncertainty、urgency、data handling正文。owner/reviewer、review note、Organization label、provider/funding evidence、content自由正文和其他Demand均禁止。

每项内部携带`repr=False`的exact canonical DemandVersion bytes，仅供adapter读后验证：严格UTF-8/无重复key/关闭root，按`demand-content-json-v1`重编码逐字一致，SHA-256等于持久hash，且上述派生值逐项等于canonical content；验证后不得进入Matching普通DTO、日志、receipt、audit或event。bytes、root/version、VERIFIED review、SECURED funding、OPEN request、全部rule IDs/selector任一缺失、重复、乱序、错绑或损坏时整批`SERVICE_UNAVAILABLE | RESOURCE_NOT_FOUND`，绝不返回partial或过滤坏行。

`captured_at`必须来自同一个`BEGIN ... READ ONLY`事务中一次`transaction_timestamp()`，以UTC返回；同批每项与result root逐字相同，不能用应用`datetime.now()`或requested_at替代。结果还逐字携带requested allowlist并证明`snapshot IDs == allowlist`、statement count恰为2。fixed SQL一次锁/验证scope、一次按UUID byte序bulk capture；不逐row查询，不写Demand/audit/outbox。

## 11. 并发、COMMIT_SENT 与恢复

expected aggregate version在root锁后CAS；同root不同命令只允许一个获胜。same receipt key同payload并发产生一个业务效果和一个exact replay；same key不同payload稳定冲突；不同key但相同client reference、submission version、review assignment、source event或OPEN matching request仍由业务unique/lock保证单效果。

COMMIT之前的serialization/deadlock/connection错误必须完整rollback，只可在最多3次、仍持有相同外部证据有效窗且尚未发送COMMIT时重试。发送`COMMIT`后连接断开属于`COMMAND_OUTCOME_UNKNOWN`：立即discard物理连接，不能在同连接rollback或重发命令。恢复只用新连接、exact receipt/source identity和retained keys读取`COMPLETED`；找到完整匹配结果则返回replay，缺失/IN_PROGRESS/损坏/不匹配则保持unknown或SERVICE_UNAVAILABLE，不能猜测失败。

备份恢复演练必须同时证明Demand catalog head、root/version/hash、receipt/source inbox、audit/outbox一致；只恢复业务表或只恢复outbox都不算可恢复。

## 12. 真实 PostgreSQL 18 TDD 证据矩阵

首轮RED测试必须：

1. 动态加载并逐项应用最终IAM catalog，验证ledger/compatibility和真实server major；
2. 用合法ACTIVE User/Session/Organization/Membership/DEMAND_OWNER/current policy acceptance建立IAM前置事实；
3. 证明未登记时Demand schema、roles和catalog不存在；
4. 让production seam import成功、dataclass frozen、repr无secret、无generic execute，且默认拒绝发生在checkout之前；
5. 覆盖十个writer program与MATCH_INPUT happy semantics；
6. 覆盖root/version append-only、submission/hash、assignment/duty/separation、funding source inbox、OPEN matching request与MATCH_INPUT allowlist；
7. 覆盖cross-tenant、伪造GUC、错误role、PUBLIC、FORCE RLS；
8. 覆盖same/different key并发、expected-version/current/hold/rule race、每个稳定write checkpoint全回滚；
9. 覆盖receipt retained-key exact replay、payload冲突、损坏persisted shape；
10. 覆盖COMMIT ack loss、discard、新连接恢复、pool reset和secret sentinel。

缺schema或default-deny只能作为测试捕获的稳定semantic observation；ImportError、fixture SQL、migration、driver、server、编程错误必须保持test error而不能包装成预期失败，也不得skip。RED精确计数与后续GREEN证据追加记录在本节和[测试与质量](/development/testing.md)，历史RED不在GREEN后删除。

当前已完成契约/domain/Memory application基线为`34/34 OK`（contract 7、domain 11、application 16）。首轮真实PG18实跑动态应用当时IAM catalog head v15，并建立合法ACTIVE Session/Organization/DEMAND_OWNER/current policy acceptance：`Ran 17 tests`、`47 failures`、`0 errors`、`0 skips`。其中immutable/default-deny contract guard通过；47项差异全部是缺Demand catalog/schema/roles/fixed SQL时的预期semantic observation（含`demand_review`错用owner CREATE、伪造startup GUC、FORCE RLS与PUBLIC ACL关闭护栏），没有ImportError、fixture SQL、migration、driver或server错误。

MATCH_INPUT复审发现单断言只证明code会产生假绿，因此在不增加方法数的前提下，将该方法从1项差异扩为54项：逐个identity/rule/hard-filter字段、canonical bytes/SHA-256、nested frozen与关闭field set、partial/corrupt构造拒绝、read-only fixed trace、same-transaction PG `transaction_timestamp()` probe、UTC和repr secret/budget/content隔离。最终唯一IAM head 15（0015 SQL SHA-256 `50df44d9aafaaaab4148e1883c2f579108a40eb145781b5e045d4dd93021373a`；manifest raw SHA/review pin `ebbdeef26c7b620750e7f9e6a064c91a520cfd83561911ed624cd57e67209b4f`）真实PG18实跑为`Ran 17 tests`、`100 failures`、`0 errors`、`0 skips`。明确只排除该Demand intentional RED后，最终head 15完整稳定storage为`144/144 OK`；文档校验为`55`个可导航页面、全contract目录`70/70 OK`。该RED不计入稳定平台GREEN总数，此时尚不能宣称Demand PostgreSQL可用。

IAM依赖缺口另经direct-SQL TDD：未登记0016的真实PG18/head15先得到`15 methods / 15 semantic failures / 0 errors / 0 skips`，每项均精确指向owner六参或reviewer七参capability不存在。首次capability GREEN后，Demand migration-runner集成又依次暴露两个默认拒绝ACL：无`infra` compatibility读取权，以及可读compatibility后仍不能在`iam_api`解析冻结签名；二者都被同一新增direct方法收敛为`1 failure / 0 errors / 0 skips`，并以“可读head/可解析签名、但无capability EXECUTE与`iam.*` SELECT”的最小授权转绿。固定测试时钟一度使已过idle deadline的Session掩盖happy path；只修独立fixture的合法时窗后，DB-derived与production builder marker逐字一致，未增加production fallback或放宽deadline。

最终IAM forward-only 0016 raw SQL SHA-256为`5bf115a9fddc55f3b2cc14bb88c6125f45a00303c75c6f21a96b3e88be868ba8`，canonical IAM manifest raw SHA-256/review pin为`8b114475a807add466a5ddd6789880641b45dcbaa2aadb0ae4aae7e1ddee2268`；v0–v15 bytes保持不变。最终direct套件为16/16 GREEN，使用独立owner与reviewer User/Session证明本文第4节的签名/返回、固定search path、PUBLIC revoke/角色ACL、锁序、八个operation target marker、cross actor/org/target/GUC、ACTIVE/deadline/revocation、old-source acceptance复用和current legal/hash语义。当前head16上排除Demand与Taxonomy各自刻意PG RED的稳定storage为160/160。这一阶段只把IAM authority依赖转绿；Demand独立catalog/schema/UoW仍以后续17方法全绿为完成条件。

随后Demand独立catalog与forward-only `0001_expand__demand_v1.sql`进入GREEN：raw SQL SHA-256为`c352e19a34ce014abb0c52aae9d082d68029a92d55d2489628787bda3f50d59f`，restricted-canonical manifest raw SHA-256/review pin为`568db4604acbad7c96d7460227311683f5acb108b5c77f597d263374e8fadaf0`，IAM依赖仍是上述唯一head16。相同17个真实PostgreSQL 18方法、全部100项既有业务oracle实跑为`Ran 17 tests in 2.498s — OK`；明确只排除Taxonomy PostgreSQL intentional RED后的完整稳定storage为`177/177 OK`（47.915s）。Demand既有contract/domain/Memory application为`34/34 OK`，完整contract discovery为`70/70 OK`。

GREEN过程中只做了TDD夹具契约修正而未放宽业务oracle：每个测试/十个writer subcase显式reset并seed最小合法graph；独立reviewer Session的label、认证时序与有效窗改为满足IAM关闭约束；review专用case使用冻结的`demand_review`角色而不再误用`demand_self`；不同key并发使用不同command identity，COMMIT acknowledgement loss在新连接上追加第二次exact replay。生产侧仍关闭拒绝错误role、过期/错marker、partial/corrupt snapshot及不完整receipt。真实pool/composition、HTTP server、worker部署与跨Context端到端启用仍是后续发布门槛，本证据不宣称这些边界已经完成。

## 13. 实现完成定义

Demand PostgreSQL切片只有同时满足以下条件才可从RED转GREEN：

- 独立forward-only catalog、raw SQL digest、manifest/review pin与wheel bytes通过；
- 所有在线角色、FORCE RLS、IAM capability和fixed SQL registry通过真实PG18；
- writer、MATCH_INPUT、并发、rollback、receipt/inbox、COMMIT unknown、pool reset和privacy矩阵全绿；
- Demand既有34项、稳定platform storage、IAM contract和docs verifier无回归；
- 文档明确保留真实pool/composition/server/E2E及外部启用门槛，不能把单机临时PG测试写成生产发布。
