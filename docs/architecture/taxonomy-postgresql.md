# Taxonomy PostgreSQL 18 持久化与生产事务设计

> 状态：Taxonomy独立PostgreSQL切片的权威详细设计；default-deny seam与真实PostgreSQL 18 semantic RED（12 methods / 50 semantic failures / 0 errors/skips）已转为production GREEN（12/12），独立migration/catalog、FORCE RLS、fixed UoW、consumer/MATCH capture与pool disposition均已实现。
> 上游事实：[Taxonomy、受控代码与规则目录](taxonomy-and-rule-catalog.md)、[Schema与存储迁移](schema-and-storage-migrations.md)、[数据与安全](data-and-security.md)。
> 不包含：公共HTTP presenter、BFF composition、Profile/Demand/Matching自己的marker写事务、任意搜索或动态分类。

## 1. 目标、边界与独立Catalog

Taxonomy Catalog保存发布后不可变的release graph和证明，不把JSON文件、事件payload或当前label当事实。PostgreSQL实现必须保持Memory已冻结的canonicalization、compatibility、状态机、receipt、checkpoint和closed event语义，同时增加真实并发、RLS、连接处置与schema compatibility门禁。

Taxonomy使用独立组件目录：

```text
desire_platform/taxonomy/adapters/postgres/migrations/
  0001_expand__taxonomy_v1.sql       # 独立v1 schema/role/RLS/function
  manifest.json                    # restricted-canonical catalog
  catalog.py / runner.py           # 独立byte-exact runner
```

IAM migration runner不得创建`taxonomy` schema、role、table、policy或function；Taxonomy runner不得写`infra.schema_migrations`中的IAM component，也不得改变IAM compatibility tuple。Taxonomy自己的`taxonomy.schema_migrations/schema_contracts/schema_compatibility`记录component、raw SQL SHA-256、restricted-canonical manifest SHA-256、runner、应用时间及机器契约digest。

启动门禁固定为：PostgreSQL major恰为18；动态IAM catalog receipt逐项匹配当前artifact；Taxonomy catalog raw bytes匹配review pin；ledger无未知/缺失/改写版本；application schema版本位于`min_app_compatible_version..max_app_compatible_version`。任一失败在checkout后、业务SQL前关闭拒绝并discard不可信连接。

## 2. Owner、登录角色与ACL

集群角色彼此独立且全部`NOBYPASSRLS`：

| role | LOGIN | 用途 | 禁止 |
| --- | --- | --- | --- |
| `taxonomy_schema_owner` | no | 拥有schema/table/function/policy | application checkout、业务流量 |
| `taxonomy_migration_runner` | yes | advisory-lock后`SET ROLE taxonomy_schema_owner`运行reviewed migration | 持久业务读写 |
| `taxonomy_publisher` | yes | Publish固定program、receipt/audit/outbox | 任意SELECT、DDL、consumer scan |
| `taxonomy_admin` | yes | Retire固定program和exact管理读 | 发布artifact改写、任意SQL |
| `taxonomy_reader` | yes | public exact ACTIVE/SUPERSEDED bundle/node/edge/label读 | current枚举、DRAFT/RETIRED、写 |
| `taxonomy_consumer` | yes | scope-bound consumer/MATCH exact artifact capture | global dump、current替换、写Catalog |

PUBLIC对`taxonomy`及未来`taxonomy_api`无USAGE、表权限或function EXECUTE。在线角色不是对象owner，不属于owner role，无CREATEROLE/CREATEDB/SUPERUSER/REPLICATION/BYPASSRLS。迁移后owner不LOGIN；migration runner不继承在线角色。`taxonomy_reader`和`taxonomy_consumer`只执行明确授予的fixed function/statement，不取得base-table broad SELECT。

## 3. Transaction-local scope与连接协议

每次checkout验证`session_user=current_user=expected role`、server major、schema compatibility和transaction IDLE，然后：

```text
BEGIN ISOLATION LEVEL READ COMMITTED
SET LOCAL TIME ZONE 'UTC'
SET LOCAL lock_timeout = '2000ms'
SET LOCAL statement_timeout = '10000ms'
SET LOCAL idle_in_transaction_session_timeout = '15000ms'
SELECT set_config('app.taxonomy_operation', ..., true)
SELECT set_config('app.workload_principal_id', ..., true)
SELECT set_config('app.workload_credential_id', ..., true)
SELECT set_config('app.taxonomy_selector_digest', ..., true)
SELECT set_config('app.taxonomy_bundle_id', ..., true)
SELECT set_config('app.consumer_code', ..., true)
SELECT set_config('app.consumer_authorization_digest', ..., true)
```

writer scope绑定SYSTEM workload、operation、attestation digest、correlation/causation/trace；reader绑定path中的exact bundle/code/pair；consumer绑定consumer code、job/workload、exact bundle+manifest hash与持久authorization allowlist。缺失、空、伪造、跨operation或非transaction-local scope都零披露/关闭拒绝。

pre-COMMIT失败必须ROLLBACK。只有transaction IDLE、`RESET ROLE/ALL`、`DISCARD TEMP`且全部`app.*`为空的连接可release。错误role/server/schema、断链、rollback/reset失败、prepared statement或temp污染一律discard。测试必须在同一physical PID连续执行不同publisher/consumer/read请求，证明scope不残留。

## 4. Schema、不可变release graph与约束

未来`taxonomy` schema至少包含：

| relation | 关键事实 |
| --- | --- |
| `families` | immutable family code、status、created_at |
| `selectors` | jurisdiction/locale-set/semantic-major/consumer-set及selector digest |
| `bundles` | semantic version、compatibility、predecessor/successor、effective window、release hash、状态/version |
| `current_bundles` | selector→唯一ACTIVE/effective bundle、pointer version |
| `release_artifacts` | kind/schema/locale/count/hash、canonical bytes或受检locator digest |
| `nodes` / `node_attributes` | code永久含义、status/replacement、关闭attribute |
| `edges` | kind/from/to/ordinal、端点与hierarchy事实 |
| `labels` | bundle/code/locale、NFC受限label字段 |
| `crosswalks` / `crosswalk_mappings` | exact source/target release与mapping cardinality |
| `signature_evidence` / `trust_evidence` / `review_approvals` | digest-bound verified evidence，不保存secret/signature body |
| `command_receipts` | versioned keyed identity/payload、安全response/ETag/status/retention |
| `audit_log` / `outbox_events` | 关闭审计与正式taxonomy-v1 envelope |
| `consumer_inbox` | source event digest、PENDING/COMPLETED、安全result |
| `consumer_authorizations` | consumer/job/workload/exact bundle allowlist与期限 |

所有业务、evidence、receipt、audit、outbox和inbox表`ENABLE ROW LEVEL SECURITY`且`FORCE ROW LEVEL SECURITY`。约束/trigger必须验证：

- family内code永久唯一；同code的kind/definition/attributes不可换义；
- `(bundle_id,code)`、edge端点、replacement、label和crosswalk全部用复合FK闭环同family/release；
- 同bundle无self/duplicate edge，层级关系无cycle；
- 同bundle/code/locale唯一label，locale coverage与selector locale digest完整；
- SemVer、predecessor、compatibility和crosswalk关系与domain validator一致；
- 同selector至多一个ACTIVE current；current必须指向ACTIVE且命中半开effective window；
- ACTIVE后release/artifact/node/edge/label/crosswalk/evidence不可UPDATE/DELETE；只有bundle状态/version、successor/retired reason按状态机推进；
- raw Idempotency-Key、workload credential、签名body、approval正文、artifact locator和自由JSON无列可存。

数据库约束是domain复验后的第二道门，不接受应用传入的“已验证”布尔值。cycle、coverage、compatibility等跨行约束在事务内deferred到固定phase boundary并显式`SET CONSTRAINTS ... IMMEDIATE`，随后不再允许写受保护release graph。

## 5. Evidence、artifact与双审批

Publish在持锁事务外从Artifact port读取exact references与bytes，逐artifact复算JCS/SHA-256和release/selector digest；验证ED25519 signature、ACTIVE trust record及两个不同reviewer的exact duty：`DOMAIN_STEWARD`与`SAFETY_DATA_STEWARD`。两项approval必须绑定同一release manifest与golden result digest，且未过期。

事务内按ID固定顺序锁signature/trust/两项approval的持久receipt，再验证：ID、key、algorithm、manifest/golden digest、reviewer独立性、状态和exclusive expiry均未漂移。evidence只保存关闭元数据与digest；签名字节、key material、provider response、review comment正文永不进入Taxonomy数据库、trace、audit或outbox。锁内撤销或漂移整事务回滚并返回关闭503/409，不允许使用事务外旧ALLOW继续发布。

## 6. Fixed SQL registry与statement budget

production seam冻结以下operation、role、statement identity与budget；当前RED只有identity，没有SQL字符串。未来GREEN每个名字只能映射一条static SQL/fixed function，禁止generic execute/query、动态identifier、请求控制ORDER BY、`SELECT *`、OFFSET、per-node N+1或按fixture分支。

| operation | role | statements | budget |
| --- | --- | --- | ---: |
| Publish | `taxonomy_publisher` | preflight；receipt claim；selector/evidence lock；release graph insert；phase boundary/current advance；audit；outbox；receipt complete | 8 |
| Retire | `taxonomy_admin` | preflight；receipt claim；bundle/current lock+retire；audit；outbox；receipt complete | 6 |
| Exact bundle | `taxonomy_reader` | exact bundle+descriptor projection | 1 |
| Exact node | `taxonomy_reader` | exact bundle/node/selected-locale/direct-edge projection | 1 |
| Exact edge pair | `taxonomy_reader` | exact bundle/from/to edge projection | 1 |
| Consumer capture | `taxonomy_consumer` | lock/validate persisted authorization；exact release+all artifacts capture | 2 |
| Consumer inbox claim | `taxonomy_consumer` | exact source claim；marker/result completion | 2 |

query-shape SHA-256覆盖`taxonomy-postgres-v1`、operation、role、statement names/order/budget。任何column/join/order/checkpoint变化必须新migration/profile version，不能原地改变digest。

## 7. Publish锁序与原子checkpoint

Publish全局锁序：

```text
1 exact receipt identity
2 family → selector → current pointer → predecessor bundle
3 candidate bundle ID
4 artifact descriptors按(kind,locale UTF-8 bytes)
5 trust → signature → approvals按duty/ID
6 permanent code rows按code UTF-8 bytes
7 nodes → edges → labels → crosswalk parent rows
8 audit → outbox → completed receipt
```

same key并发在receipt unique等待，赢家完成后输家只允许exact replay或`IDEMPOTENCY_KEY_REUSED`。different key同selector由current pointer串行；第二个old expected-current必须`PRECONDITION_FAILED`且无receipt/audit/outbox。不同selector不能因global table/advisory lock互相串行。

Publish必须保持Memory冻结的13个logical checkpoint：

```text
receipt.pending
bundle.insert
artifacts.insert
nodes.insert
edges.insert
labels.insert
crosswalk.insert_optional
predecessor.supersede_optional
current.advance
audit.append
outbox.append
receipt.complete
commit
```

nodes/edges/labels分别是一个受检bulk statement而非动态item checkpoint。任一点故障后，独立owner snapshot逐表比较bundle/current/artifacts/nodes/edges/labels/crosswalk/evidence/receipt/audit/outbox完全等于调用前，且无可见PENDING receipt。成功初发创建ACTIVE/v1/current；替代在同事务创建successor ACTIVE、predecessor SUPERSEDED/v+1、current advance及Published/Superseded/optional CrosswalkPublished事件。

## 8. Retire、终态与读取

Retire只允许ACTIVE或SUPERSEDED，比较expected bundle version，保存关闭reason；若目标是current则同事务清除pointer。固定7 checkpoint为：

```text
receipt.pending / bundle.retire / current.clear_if_current /
audit.append / outbox.append / receipt.complete / commit
```

RETIRED终态，不能重新ACTIVE、SUPERSEDE或修改artifact。public exact read只返回ACTIVE/SUPERSEDED；DRAFT/RETIRED、未知bundle/code、错误locale统一零行/关闭404，不泄漏存在性。projection严格匹配已发布OpenAPI DTO，不含definition正文、signature/trust/approval、canonical bytes、locator、current pointer或其他bundle列表。

## 9. RLS与exact fixed projection

policy同时绑定`session_user/current_user`、transaction-local operation与exact scope。单靠`current_setting`、bundle外键存在或caller传入ID不构成authority。直接table、join、subquery、CTE、view、prepared statement和function调用必须得到相同闭包；FORCE RLS也约束owner直接访问，迁移维护只能显式受审流程。

`taxonomy_reader`：只能读取path绑定的ACTIVE/SUPERSEDED exact bundle、node或edge pair；禁止selector/current/global code枚举。`taxonomy_consumer`：只有持久`consumer_authorizations`中同consumer/job/workload/exact bundle+manifest且未过期的allowlist；caller扩大候选不增加结果。普通publisher/admin不能使用consumer capture，consumer不能调用Publish/Retire。

伪operation、错误workload、错误consumer、错误bundle/hash、future/expired authorization、inactive/retired bundle、跨selector与scope复用均零披露或关闭错误。在线角色不因row owner、GUC或function owner获得BYPASS。

## 10. Consumer与MATCH closed capture

consumer先durable claim exact source envelope digest，再通过Catalog fixed capture读取exact release与全部artifact；event payload永远不是artifact body。验证family/schema/semantic major、bundle/status/effective window、manifest/selector/artifact hashes与item counts后，在consumer自己的事务写marker、inbox COMPLETED及本地audit/outbox。same event exact replay不重复marker；同event ID不同digest、partial artifact、unsupported major或hash drift整批503/compatibility error且回滚。

MATCH使用同一`taxonomy_consumer` profile但`consumer_code=MATCHING`和独立authorization digest。返回关闭`TaxonomyPostgresConsumerRelease`：bundle identity/version/status/compatibility、manifest/selector digest，以及repr-hidden的完整immutable nodes/edges/labels/crosswalk canonical facts。它不返回current selector、review evidence、artifact locator、其他consumer authorization或任意search。按bundle/code raw UTF-8 bytes排序；任一row损坏使整批关闭失败，不返回健康partial。

## 11. Receipt、COMMIT_SENT与恢复

receipt identity绑定SYSTEM principal、operation、command version、raw key经retained identity key HMAC；payload HMAC覆盖method、canonical path、target/selector、expected version/current、schema和关闭body。row保存canonicalization/command version、identity/payload key IDs和digest、安全response schema/status/ETag、target/version、PENDING/COMPLETED及retention；不保存raw key或credential。

completed replay仍验证当前ACTIVE workload credential，但跳过artifact/signature/approval/domain重验；逐字读取并关闭验证safe response。same identity不同payload为`IDEMPOTENCY_KEY_REUSED`；未知key/schema、损坏body/ETag/target/version、多行或持续PENDING为503。

adapter在driver发送COMMIT前切换`WRITING→COMMIT_SENT`。之后任何driver/timeout/连接错误只能discard一次并抛`COMMAND_OUTCOME_UNKNOWN`；禁止ROLLBACK、RESET、release、同连接查询receipt或request内重试。上层用same key和新physical connection恢复：server已提交则exact replay，未提交才重新claim。ack-loss测试必须先让PG处理COMMIT，再断socket；trace中COMMIT后无SQL。

## 12. Audit、outbox、inbox与隐私

audit保存operation、SYSTEM actor/original actor、target、result、correlation/causation/trace、manifest/evidence aggregate digest和计数，不保存artifact正文、label/definition、signature/approval ID正文或secret。outbox只保存正式`taxonomy-v1.schema.json`关闭envelope；节点/边/label/crosswalk正文由consumer exact read取得。

secret sentinel递归扫描request repr、exception、trace、receipt、audit、outbox、inbox、所有普通text/json/bytea列和projection：raw Idempotency-Key、workload credential、signing material、approval comment、artifact locator/provider response、个人/组织/精确位置均零命中。只有reviewed immutable artifact relation可保存机器taxonomy facts；这些事实也不得复制到receipt/audit/outbox/trace。

## 13. 真实PostgreSQL 18 semantic RED→GREEN门禁

RED测试启动真实PG18，动态加载当前IAM catalog并逐项核对ledger/head；确认IAM没有越界创建Taxonomy schema。测试再检查未来独立Taxonomy catalog seam：若不存在manifest，保持`catalog/report=None`且不伪造migration；若未来存在，则动态load/run并要求receipt exact。合法initial/minor release、SYSTEM scope、signature/trust/双approval、receipt和consumer allowlist由独立support构建。

RED阶段只有exact `TAXONOMY_POSTGRES_BEHAVIOR_NOT_AVAILABLE`可转换为semantic observation；GREEN后production entry point不再抛该sentinel。ImportError、PostgreSQL启动、IAM migration、fixture、psycopg、SQL、schema validator或编程错误始终必须是test error；不得skip、owner/BYPASS/Memory fallback、测试环境SQL分支或吞异常。结构测试同时证明immutable request/settings/profile、固定role/statement budget/query-shape digest、无generic execute，以及production checkout/RESET/release或discard的精确处置。

本阶段禁止创建`taxonomy/adapters/postgres/migrations/manifest.json`或任何SQL、修改IAM/Profile/Demand migration bytes与review pin、扩共享runner catalog，或为通过RED创建空schema/table/policy。取得精确methods/failures/errors/skips并把证据写回本页后停止，等待独立GREEN授权。

## 14. DESIGN → TEST → CODE trace

| DESIGN | TEST | 当前CODE | 当前状态 |
| --- | --- | --- | --- |
| independent catalog/roles · §1–2 | `TEST-DB-TAXONOMY-CATALOG-001` | v1 catalog、review pin/ledger/role preflight | GREEN |
| schema/immutability · §4–5 | `TEST-DB-TAXONOMY-GRAPH-001` | immutable release/evidence graph、current phase constraint | GREEN |
| fixed publish/retire · §6–8 | `TEST-DB-TAXONOMY-UOW-001` | explicit programs、13/7 checkpoints、current CAS | GREEN |
| FORCE RLS/read · §2/9 | `TEST-DB-TAXONOMY-RLS-001` | role/scope/authority-bound exact projections | GREEN |
| receipt/concurrency · §7/11 | `TEST-DB-TAXONOMY-CONCURRENCY-001` | same/different key、replay/conflict/retained key、COMMIT_SENT recovery | GREEN |
| consumer/MATCH · §10 | `TEST-DB-TAXONOMY-CONSUMER-001` | inbox、artifact+relation closed reconstruction、unsupported major | GREEN |
| privacy/pool · §3/12 | `TEST-SEC-TAXONOMY-PG-001` | physical connection reset/discard与全surface secret sentinel | GREEN |

## 15. 2026-08-08 PostgreSQL 18 semantic RED证据

`storage.postgres.test_taxonomy_postgres_red`使用`TemporaryPostgres18`启动真实server，动态应用IAM v0–v15并逐项核对ledger与compatibility head。IAM依赖证据为：`0015_expand__creator_profile_authority.sql` raw SHA-256 `50df44d9aafaaaab4148e1883c2f579108a40eb145781b5e045d4dd93021373a`；IAM restricted-canonical manifest SHA-256/review pin `ebbdeef26c7b620750e7f9e6a064c91a520cfd83561911ed624cd57e67209b4f`。setup还证明IAM没有创建`taxonomy` schema；独立Taxonomy future catalog seam存在，但当前无`manifest.json`、SQL、layout、review pin或migration report。

合法fixture使用已GREEN的initial release及本地复算的manifest/artifact canonical bytes与SHA、SYSTEM workload scope、ED25519 signature receipt、ACTIVE trust、两个不同reviewer的exact approval、versioned receipt和MATCH consumer authorization。production surface冻结七个explicit entry point、四个online role、固定statement budget/query-shape digest、Publish 13与Retire 7 checkpoint、immutable/repr-hidden request/result以及commit-unknown类型；唯一default-deny sentinel在connection checkout前触发。结构方法证明零checkout、无generic execute/query、secret-safe repr与未来catalog seam exact deny，单独GREEN。

有效命令：

```bash
cd platform
PYTHONPATH=src:tests uv run python -m unittest \
  storage.postgres.test_taxonomy_postgres_red -q
```

精确结果为`Ran 12 tests`、`50 failures / 0 errors / 0 skips`；12个方法中1个结构/default-deny方法GREEN，其他11个方法的50条subtest failure全部来自未来业务/事务事实与`TAXONOMY_POSTGRES_BEHAVIOR_NOT_AVAILABLE`或缺失独立catalog/schema/roles的差异：catalog/roles/FORCE RLS 5、publish/evidence/immutable graph 6、exact reader/RLS 4、双连接selector/receipt claim 2、replay/conflict/retained keys 3、Publish 13+Retire 7 checkpoint rollback 20、COMMIT_SENT discard/recovery 3、consumer inbox/MATCH exact capture 4、pool/role/privacy 3。

ImportError、PostgreSQL启动、IAM migration、catalog解析、fixture/dataclass、psycopg、SQL和编程错误均为零，也没有skip。测试没有创建空Taxonomy schema或role、没有owner/BYPASS/Memory fallback、没有测试环境SQL分支，且未修改任何IAM/Profile/Demand migration/catalog/manifest/review pin。本切片在RED停止，不能据此宣称Taxonomy PostgreSQL、RLS、production pool或consumer persistence已实现。

## 16. 2026-08-08 PostgreSQL 18 GREEN证据

GREEN保持原12个方法及50条业务oracle；结构seam从RED期的checkout前sentinel转换为production事务事实。独立Taxonomy catalog只登记v1：`0001_expand__taxonomy_v1.sql` raw SHA-256为`256114bfca4449412a3bc7a1cc9ff095c2d5e2a8f25783e96da988b58f7c503e`，restricted-canonical `manifest.json` SHA-256与review pin均为`c0580dc5f34022c0a3bcfb7489de39468e973e546c1601cea4dfec729ed14f70`。runner写入独立`taxonomy.schema_migrations/schema_contracts`，没有修改IAM/Profile/Demand migration bytes、manifest或review pin。

动态IAM依赖已推进至最终head16：`0016_expand__demand_authority.sql` raw SHA-256为`5bf115a9fddc55f3b2cc14bb88c6125f45a00303c75c6f21a96b3e88be868ba8`，IAM manifest/review pin为`8b114475a807add466a5ddd6789880641b45dcbaa2aadb0ae4aae7e1ddee2268`。Taxonomy setup从catalog entries派生版本并逐项核对ledger/head，因此后续forward-only IAM head不会要求改Taxonomy常量。

production UoW实现exact role/server/schema compatibility preflight、transaction-local digest scope、持久workload authority窄`SECURITY DEFINER`锁、receipt-first与selector/current固定锁序、13/7 checkpoint、closed response replay、different-payload冲突、正式四事件中的适用event集合、审计/outbox和`COMMIT_SENT` discard。FORCE RLS同时绑定session/current role、operation、exact scope与持久authority；current phase trigger关闭拒绝future/inactive current、artifact count/label coverage/replacement/cycle损坏。consumer/MATCH从release JSON、canonical artifact bytes/hash与关系行三方独立重建，任何partial/drift整批503。

RED期default-deny掩盖的arrange问题按批准范围修正但没有改变业务结果：每个test/subcase先admin reset；Publish/Retire seed exact ACTIVE workload authority，Retire另seed ACTIVE/current release，consumer seed exact allowlist；expired evidence改用server-now相对窗口；immutability只窄捕获`psycopg.DatabaseError`且要求SQLSTATE `23514`与完整graph snapshot不变；COMMIT三案显式区分server processed/durable与ack-loss，并用新physical connection恢复。测试pool关闭driver自动prepare、复用released physical connection，并对污染、RESET/`app.*`残留执行discard门禁。

精确回归：

- `storage.postgres.test_taxonomy_postgres_red`：12/12 GREEN，0 failures/errors/skips；
- Taxonomy domain/application Memory：26/26 GREEN；
- `tests/contract`：70/70 GREEN；
- `tests/storage`排除明确intentional RED的`storage.postgres.test_demand_postgres_red`：172/172 GREEN。

本证据只关闭Taxonomy独立PostgreSQL catalog、production repository/UoW、RLS、pool、consumer/MATCH capture；HTTP presenter、consumer本地marker数据库与跨Context E2E仍按主设计后续切片交付。
