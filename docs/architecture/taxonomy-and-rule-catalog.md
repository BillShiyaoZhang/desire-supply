# Taxonomy、受控代码与规则目录

> 状态：目标平台 Taxonomy & Rule Catalog Context 权威设计；OpenAPI、事件与五份领域机器契约已完成contract-first RED→GREEN（11/11）；immutable domain/application/ports seam及Memory domain/application行为已完成semantic RED→GREEN（26/26）；独立PostgreSQL详细设计、migration/catalog、production UoW、FORCE RLS与真实PG18 semantic RED→GREEN（12/12）已提交。生产consumer本地marker adapter、HTTP实现与跨Context E2E尚未提交。
> 适用范围：领域/技能/问题/地区/语言/数据敏感度等受控代码，TaxonomyBundle发布、兼容、弃用、crosswalk、消费者marker与历史复算。
> 不包含：Matching权重/预算规则发布、PolicyBundle法律文本、任意用户标签、全文搜索或AI自动分类。

## 1. 目标与事实所有权

Profile、Demand、Matching、Project、Trust和Analytics都使用受控code。若每个Context各自复制JSON文件或把label当事实，会产生同一code不同含义、历史hash无法复算、已发布资料被“改翻译”改变语义等问题。

Taxonomy Context拥有：

- `TaxonomyFamily` 的稳定身份和允许的node kinds；
- immutable `TaxonomyBundle`、node/edge/label artifact及发布证据；
- selector current、effective window与supersession链；
- bundle之间的显式`TaxonomyCrosswalk`；
- consumer同步marker与ack，不拥有consumer业务内容；
-发布receipt、audit、outbox和公共安全读取投影。

Consumer继续拥有ProfileVersion/DemandVersion/MatchRun等事实。它们永久保存exact `taxonomy_bundle_id`和content hash，不从“当前taxonomy”重算历史。Catalog不能直接更新consumer row。

## 2. TaxonomyBundle

状态`DRAFT / ACTIVE / SUPERSEDED / RETIRED`。selector至少为：

```text
family_code / jurisdiction_code / locale_set_digest
semantic_major / intended_consumer_set_digest
```

同selector当前恰一个ACTIVE/effective bundle。bundle保存：

| 字段 | 规则 |
| --- | --- |
| `bundle_id/semantic_version` | Opaque ID；SemVer正规字符串，major含义变化 |
| `family_code` | 例如`PLATFORM_WORK_V1`，稳定且不可复用 |
| `canonicalization_version` | `taxonomy-release-json-v1` |
| `node_manifest_sha256` | ordered nodes canonical bytes |
| `edge_manifest_sha256` | ordered relations canonical bytes |
| `label_manifest_sha256` | locale labels canonical bytes；label不等于code语义 |
| `selector_digest/release_manifest_sha256` | 本地独立复算 |
| `effective_at/effective_until` | UTC半开窗口；首发按发布政策生效 |
| `predecessor_bundle_id` | 替代时exact predecessor；同selector |
| `publisher/trust/approval` | SYSTEM workload、签名key与review approval引用 |

ACTIVE后bundle的selector、nodes、edges、labels、hash和发布证据不可变；只能ACTIVE→SUPERSEDED/RETIRED并设置successor/terminal事实。修正拼写也发布新bundle，不原地改历史bytes。

## 3. Node、Edge与Label

### 3.1 TaxonomyNode

关闭字段：

```text
code / kind / definition_code
status = ACTIVE | DEPRECATED
introduced_in_bundle_id
deprecated_reason_code / replacement_codes[]
attributes[]
```

`code`为2..64 ASCII大写字母、数字、`_.:-`，全局在family内永久唯一且不可换义。`kind`首版关闭为：

```text
DOMAIN / PROBLEM_TYPE / TASK / SKILL / SKILL_LEVEL
TARGET_USER_CATEGORY / WORK_MODE / FEEDBACK_CADENCE
TEAM_PREFERENCE / REGION / LANGUAGE / DATA_SENSITIVITY
AI_USE / RISK / DELIVERY_KIND / REVIEW_REASON
```

`definition_code`指向reviewed定义artifact，不把自由正文作为机器语义。`attributes`是按kind关闭的key/value code或整数，不允许任意map。示例：SKILL可有`skill_family_code`；REGION可有`country_code`；DATA_SENSITIVITY可有有序`classification_rank`。

DEPRECATED node仍可解析历史，不能从bundle中删除；新消费是否允许由consumer policy决定。replacement可0..5项且只指向同family已存在code；一对多不是自动迁移。

### 3.2 TaxonomyEdge

关闭为`{edge_kind,from_code,to_code,ordinal}`；kind为：

- `BROADER_THAN / NARROWER_THAN`：有向无环层级，二者不双写；
- `REQUIRES / INCOMPATIBLE_WITH`：consumer可用守卫；
- `RELATED_TO`：只用于解释/发现，不能成为授权或hard filter事实；
- `ALLOWED_LEVEL`：Skill到SkillLevel；
- `LOCATED_IN`：Region层级。

禁止self edge、重复edge、层级cycle和跨family隐式引用。不同kind的对称/传递语义在release schema固定，consumer不能自行推断未发布edge。

### 3.3 TaxonomyLabel

label关闭为`{code,locale,short_label,description?,accessibility_label?}`，NFC、控制字符禁止、UTF-8 byte上限。locale使用受控BCP-47；同bundle/code/locale恰一label。机器判断永远用code，排序默认code byte序或规则声明，不用locale collation。

label可因翻译修正随新bundle变化，但历史UI/export应能按保存bundle读取当时label；若不可用，显示code而不借当前label冒充历史。

## 4. Canonical release

release artifact拆为关闭文件：

```text
taxonomy-release-v1.json
taxonomy-nodes-v1.json
taxonomy-edges-v1.json
taxonomy-labels-v1.<locale>.json
taxonomy-crosswalk-v1.json        # 替代时可选
```

规则：

- nodes按`(kind,code)` UTF-8 byte序；edges按`(edge_kind,from_code,to_code,ordinal)`；labels按`(locale,code)`；
- 所有数组顺序属于canonical bytes，发布validator拒绝未排序而不静默修复；
- JSON只允许null/bool/拒绝bool的整数/字符串/数组/对象，无float；
- 全部对象additionalProperties false，字符串NFC且无控制字符；
- 每个artifact独立SHA-256，release manifest再覆盖ordered artifact descriptors；
- signature envelope、workload attestation与legal/domain review approval在事务外验证，并全量绑定manifest digest；
-至少两个独立review duty：domain steward确认含义，safety/data steward确认受保护属性、歧视和隐私风险。

发布前validator执行code/edge/ref完整性、cycle、replacement、locale coverage、consumer compatibility和golden content fixtures。签名正确但结构/语义非法仍拒绝。

## 5. 兼容与Crosswalk

兼容等级关闭为：

- `INITIAL`：selector首个bundle，没有predecessor或crosswalk；
- `PATCH_COMPATIBLE`：只新增label修正或不改变机器判断的安全元数据；仍发布新bundle；
- `MINOR_COMPATIBLE`：新增code/edge，旧code语义不变；旧consumer可继续使用旧bundle；
- `MAJOR_BREAKING`：删除新输入资格、换义、拆分/合并或consumer必须改schema/engine。

只有`predecessor_bundle_id=null`的首发release可使用`INITIAL`，且SemVer必须为`1.0.0`；有predecessor时禁止`INITIAL`。Crosswalk本身只使用PATCH/MINOR/MAJOR三种两版本关系，不接受`INITIAL`。

Crosswalk每项：

```text
source_bundle_id / source_code
target_bundle_id / target_codes[]
mapping_kind = EXACT | NARROWER | BROADER | SPLIT | MERGE | NO_SUCCESSOR
confidence_code / review_reason_code
```

Crosswalk是提示与受控migration输入，不自动重写Profile/Demand。`EXACT`也要求source/target定义hash满足validator；SPLIT/MERGE需要User或运营明确选择，不能自动取第一项。Matching只有rule bundle明确声明兼容pair并保存crosswalk ID/hash时才能把两个bundle输入同一run，否则`TAXONOMY_BUNDLE_CHANGED`。

## 6. Consumer marker与运行边界

每个consumer schema保存只读marker：

```text
consumer_code / taxonomy_bundle_id
release_manifest_sha256 / compatibility_level
activated_at / source_event_id / aggregate_version
```

marker只由authenticated SYSTEM consumer处理`TaxonomyBundlePublished`并通过Catalog exact read port取得完整artifact；事件不是正文。consumer在同事务验证自己支持schema/family/major和hash，再写marker。业务writer只能引用ACTIVE marker，不直接读取Catalog表或接受客户端声称“当前bundle”。

Profile/Demand保存草稿时允许当前marker；publish/submit再次锁marker并验证未漂移。旧草稿使用被supersede bundle时返回`TAXONOMY_BUNDLE_CHANGED`并要求明确迁移；系统不能在锁内自动替换codes。

MatchRun需要Demand/Profile bundle兼容。exact同bundle最简单；不同bundle必须由MatchingRuleBundle列出受检crosswalk和两侧manifest hash，并保存转换后的完整input snapshot。历史run不受current marker改变。

### 6.1 Domain validator与状态机

Domain层没有网络、数据库、时钟或签名key依赖。它接收已冻结的release/nodes/edges/labels/crosswalk值与显式`server_now`，按固定顺序返回一个深度不可变`ValidatedTaxonomyRelease`：

1. 逐artifact验证关闭shape、NFC、控制字符、整数非bool、字符串byte上限；
2. 验证输入数组已按第4节byte序，拒绝而不自动排序；
3. 复算各artifact canonical bytes/count/SHA-256与outer descriptor；
4. 验证family/bundle/locale身份全链、code永久唯一、node kind对应attribute allowlist；
5. 验证edge端点、self/duplicate、kind语义和hierarchy cycle；
6. 验证DEPRECATED replacement、labels locale coverage与crosswalk source/target；
7. 对比exact predecessor snapshot，拒绝code换义，并独立推导compatibility level与SemVer增量；
8. 复算selector bytes/digest与完整release manifest bytes/digest。

任何一步失败只返回关闭domain code`TAXONOMY_RELEASE_INVALID`或`TAXONOMY_COMPATIBILITY_REJECTED`及安全field path/reason code；不得附输入值、label、definition、mapping或canonical bytes。validator不验证signature、workload、trust和approval，那些属于application ports；签名正确也不能跳过上述domain验证。

持久`TaxonomyBundle`只允许：不存在→ACTIVE/v1、ACTIVE→SUPERSEDED/v2并绑定唯一successor、ACTIVE或SUPERSEDED→RETIRED/v+1。线上Publish transaction不会先提交一个半成品DRAFT；`DRAFT`只属于隔离review workspace的候选artifact，不能进入current selector、公开读取、consumer sync或业务FK。SUPERSEDED历史可读但不能重新ACTIVE；RETIRED终态。替代事务必须同时创建successor ACTIVE、推进current pointer并把predecessor置SUPERSEDED；任一事实不能单独提交。

### 6.2 Application命令与原子写点

`PublishTaxonomyBundle`、`RetireTaxonomyBundle`与`ApplyTaxonomyBundleToConsumer`使用三个独立handler，不提供通用CRUD。Publish固定顺序：

```text
SYSTEM workload authenticate + operation attestation
→ canonical request / retained receipt key preflight
→ completed receipt exact replay or payload conflict
→ artifact bytes exact read
→ signature trust + two independent approvals outside UoW
→ domain full validation and local digest recomputation
→ begin UoW; lock selector/current/predecessor/receipt
→ recheck trust/approval validity and current facts
→ persist bundle + artifact facts + nodes/edges/labels/crosswalk
→ predecessor supersede + current advance
→ audit + closed outbox events + completed receipt
→ one COMMIT
```

completed replay仍要求当前SYSTEM operation credential有效，但跳过artifact、signature、approval和domain重验；逐字读取持久safe response/status/schema/ETag，不能按当前selector重算。新key流程的外部验证不得发生在持锁UoW内。锁内trust/approval撤销或current漂移回滚后，以关闭409/412/422/503收口；不能拿旧验证结果发布。

Publish checkpoint固定为：`receipt.pending / bundle.insert / artifacts.insert / nodes.insert / edges.insert / labels.insert / crosswalk.insert_optional / predecessor.supersede_optional / current.advance / audit.append / outbox.append / receipt.complete / commit`。批量nodes/edges/labels各是一个logical checkpoint和一条受检bulk program，不按item制造动态checkpoint。Retire固定为`receipt.pending / bundle.retire / current.clear_if_current / audit.append / outbox.append / receipt.complete / commit`。任一点故障都要求全部关系与receipt/audit/outbox回到调用前snapshot。

Consumer handler先以durable inbox claim exact event envelope，再通过Catalog port读取exact release与全部artifact，复算hash并验证consumer支持family/schema/major；随后只在consumer自己的事务写marker、inbox COMPLETED和其本地audit/outbox。事件payload永远不能替代artifact read。same event exact replay零重复marker；同event ID不同digest、unsupported major、partial artifact或current已变化都fail closed，且不自动升级既有业务版本。

## 7. API与读投影

公开读取仅用于已知bundle/code：

```text
GET /v1/taxonomy-bundles/{bundle_id}
GET /v1/taxonomy-bundles/{bundle_id}/nodes/{code}
GET /v1/taxonomy-bundles/{bundle_id}/nodes?kind=&cursor=&limit=
```

只返回ACTIVE/SUPERSEDED的immutable bundle、node/edge/label安全DTO和强content hash；DRAFT/RETIRED按policy不可公开。cache为public immutable且path绑定bundle ID；没有全局“current所有词表”匿名枚举。locale必须是该bundle已发布locale，不能由Accept-Language偷偷换selector；缺locale返回关闭错误或code fallback。

发布/retire为内部SYSTEM命令，无公共浏览器route。管理review UI只看release diff/定义/labels/golden results，不取得signing credential或动态SQL。

## 8. PostgreSQL与RLS

PostgreSQL 18的独立catalog、roles、不可变relation、FORCE RLS、fixed SQL、事务锁序、receipt/COMMIT_SENT与consumer/MATCH capture详细裁决及12/12真实GREEN证据见[Taxonomy PostgreSQL 18 持久化与生产事务设计](taxonomy-postgresql.md)。该证据关闭Catalog数据库与production UoW，但不代表HTTP、consumer本地marker或跨Context composition已完成。

独立`taxonomy` schema包含families、bundles/current selectors、nodes、edges、labels、crosswalks、release artifacts、approvals、receipts/audit/outbox。全部ENABLE+FORCE RLS。

- public reader仍是在线application role的exact bundle transaction profile，不是SQL PUBLIC；
- publisher只执行`taxonomy_api.publish_bundle_v1`固定函数，SYSTEM workload/trust/approval在调用前验证且函数再校验exact artifacts；
- consumer sync role只读exact ACTIVE/SUPERSEDED bundle+artifact，不能全表dump或写Catalog；
- PUBLIC无schema/table/function权限，在线role非owner/NOBYPASS；
- partial unique保证selector唯一ACTIVE，复合FK保证node/edge/label/crosswalk parent与bundle一致；
- deferred triggers验证cycle、replacement/current/supersession和immutable published artifact；
- definition/label正文大小受列/check约束，发布后immutable。

真实PG18并发覆盖双publish/current replacement、同code错义、edge cycle、cross-bundle FK、伪selector GUC、public exact bundle、consumer scope和COMMIT_SENT receipt恢复。

## 9. 事件、审计与隐私

关闭事件：

- `TaxonomyBundlePublished(bundle_id,family_code,semantic_version,selector_digest,release_manifest_sha256,effective_at,status)`；
- `TaxonomyBundleSuperseded(bundle_id,successor_bundle_id,status)`；
- `TaxonomyBundleRetired(bundle_id,status,reason_code)`；
- `TaxonomyCrosswalkPublished(crosswalk_id,source_bundle_id,target_bundle_id,manifest_sha256)`。

事件不含nodes/edges/labels/definition/signature/approval正文；consumer exact read。Audit保存publisher workload、review approvals、artifact hashes、diff counts、golden result hash和结果，不保存签名材料。

Taxonomy默认不应包含姓名、组织、精确位置或受保护属性。若未来分类涉及敏感/受保护属性，必须新设计用途、合法依据、可见性和公平性门禁，不能用普通node attributes偷偷加入。

## 10. 首版机器契约

首版必须同时发布以下机器文件，不能只发布OpenAPI后让实现自行解释release JSON：

```text
platform/contracts/api/taxonomy-v1.openapi.yaml
platform/contracts/events/taxonomy-v1.schema.json
platform/contracts/domain/taxonomy-release-v1.schema.json
platform/contracts/domain/taxonomy-nodes-v1.schema.json
platform/contracts/domain/taxonomy-edges-v1.schema.json
platform/contracts/domain/taxonomy-labels-v1.schema.json
platform/contracts/domain/taxonomy-crosswalk-v1.schema.json
```

全部JSON Schema使用draft 2020-12，根与嵌套对象均`additionalProperties: false`，关闭枚举不接受未知值。Opaque ID为16..128字符的`[A-Za-z0-9][A-Za-z0-9_-]*`；SHA-256为64位小写hex；时间为带`Z`的UTC RFC 3339；整数拒绝JSON bool，任何release文件都不能表示float、binary、HTML、URI、credential或provider locator。

### 10.1 release与artifact签名面

`taxonomy-release-v1`根字段逐字固定为：

```text
schema_version = 1
canonicalization_version = taxonomy-release-json-v1
bundle_id / family_code / semantic_version
selector = {
  jurisdiction_code,
  locale_set_digest,
  semantic_major,
  intended_consumer_set_digest,
  selector_digest
}
compatibility_level
predecessor_bundle_id
effective_at / effective_until
artifacts[]
```

`release_manifest_sha256`不进入自身签名面；publisher对上述对象做JCS UTF-8后本地计算并与外部签名、trust和approval绑定的digest比较。`artifacts[]`按`(artifact_kind,locale-or-empty)`的UTF-8 bytes排序，恰有一个`NODES`、一个`EDGES`、每个已声明locale恰一个`LABELS`，可选一个`CROSSWALK`。descriptor字段只有`artifact_kind/schema_name/locale/sha256/item_count`；没有正文、路径、bucket、URL或签名。

四类artifact根分别固定为：

- nodes：`schema_version/canonicalization_version/bundle_id/family_code/nodes[]`；
- edges：`schema_version/canonicalization_version/bundle_id/family_code/edges[]`；
- labels：`schema_version/canonicalization_version/bundle_id/family_code/locale/labels[]`；
- crosswalk：`schema_version/canonicalization_version/crosswalk_id/source_bundle_id/target_bundle_id/compatibility_level/mappings[]`。

每个artifact独立JCS与SHA-256。release validator必须比较descriptor的schema、locale、count和digest；不能只验证外层signature，也不能把输入排序后接受。`selector_digest`由关闭selector对象的`taxonomy-selector-json-v1` bytes独立复算，不能信任请求字段。SemVer只接受无前导零的`major.minor.patch`；`semantic_major`必须与其major相等，compatibility level与predecessor差分必须由validator复算一致。

### 10.2 HTTP operation与DTO

公开读取只保留下列四个exact-resource operation：

| operationId | method/path | 成功DTO与缓存 |
| --- | --- | --- |
| `getTaxonomyBundle` | `GET /v1/taxonomy-bundles/{bundle_id}` | `TaxonomyBundleDto`；ACTIVE/SUPERSEDED；strong ETag与`public, immutable` |
| `getTaxonomyNode` | `GET /v1/taxonomy-bundles/{bundle_id}/nodes/{code}` | `TaxonomyNodeDto`；exact locale query；strong ETag |
| `listTaxonomyNodes` | `GET /v1/taxonomy-bundles/{bundle_id}/nodes?kind=&locale=&cursor=&limit=` | `TaxonomyNodePageDto`；code byte序keyset cursor |
| `getTaxonomyCrosswalk` | `GET /v1/taxonomy-bundles/{source_bundle_id}/crosswalks/{target_bundle_id}` | `TaxonomyCrosswalkDto`；exact pair/hash；strong ETag |

没有`GET /taxonomy-bundles`、匿名current selector、自由search、任意filter/sort/include或Accept-Language selector。cursor为版本化keyed token，绑定operation、bundle、kind、locale、last code、limit、schema/key ID及expiry；不存在、失效、不同参数复用统一`INVALID_CURSOR`且不回显内容。

内部发布面只允许受认证SYSTEM workload调用：

```text
POST /internal/v1/taxonomy-bundles:publish
POST /internal/v1/taxonomy-bundles/{bundle_id}:retire
```

Publish请求字段只有`release_manifest_sha256/signature_envelope_id/trust_record_id/domain_approval_id/safety_data_approval_id`和exact artifact references；server从受控artifact port读取bytes并全部复算。Retire请求只有关闭`reason_code`。两者要求`Idempotency-Key`，receipt存versioned keyed digest与canonical payload hash，不存raw key；Publish以当前selector/predecessor作为If-Match事实，不能用body actor/role/org或客户端时间。

`TaxonomyBundleDto`只含身份、selector安全字段、status/version/effective window、artifact hashes/counts和predecessor/successor ID；不含signature、approval、workload credential或definition正文。`TaxonomyNodeDto`含code/kind/definition_code/status/replacements/关闭attributes、所选locale label和与该node直接相关的安全edge摘要；机器consumer必须走exact artifact port，不能从分页DTO重建release。

### 10.3 错误、事件与数据库访问profile

公开read只声明`400 INVALID_REQUEST/INVALID_CURSOR`、`404 RESOURCE_NOT_FOUND`与`503 SERVICE_UNAVAILABLE`。内部Publish/Retire再声明`401 AUTHENTICATION_REQUIRED`、`403 ACCESS_DENIED`、`409 INVALID_STATE_TRANSITION/IDEMPOTENCY_KEY_REUSED/TAXONOMY_SELECTOR_CONFLICT/TAXONOMY_RELEASE_INVALID`、`412 PRECONDITION_FAILED`、`422 REVIEW_APPROVAL_REQUIRED/TAXONOMY_COMPATIBILITY_REJECTED`和`503 SERVICE_UNAVAILABLE`。错误对象固定`code/message/trace_id/field_issues`，不输出code/label/definition/signature/approval原值或SQL细节。

事件schema复用关闭envelope：`event_id/event_type/schema_version/occurred_at/aggregate_type/aggregate_id/aggregate_version/actor_kind/actor_id/original_actor_id/correlation_id/causation_id/trace_id/organization_id/payload`。Taxonomy事件的`organization_id`固定null；payload逐项只能是第9节列出的最小ID/hash/status/count事实。artifact正文、label、definition、crosswalk mapping、signature和approval不在事件schema中可表示。

OpenAPI还必须发布三个`x-taxonomy-database-access` profile：

- `PUBLIC_EXACT_TAXONOMY_READ`：`taxonomy_reader`，只读path绑定的ACTIVE/SUPERSEDED bundle/code/pair，禁止global selector与dynamic SQL；
- `TAXONOMY_PUBLISH`：`taxonomy_publisher`，只执行Publish/Retire fixed program与exact selector lock；
- `TAXONOMY_CONSUMER_SYNC`：`taxonomy_consumer`，只按事件中的exact bundle ID读取完整immutable artifact，禁止列表或任意family scan。

三个profile均要求固定`search_path=[pg_catalog,taxonomy,pg_temp]`、PUBLIC无EXECUTE/USAGE、在线role非owner/NOBYPASSRLS、参数化静态SQL和transaction-local scope reset。后续PostgreSQL测试必须逐字验证这些机器扩展与实际role/function/catalog一致。

## 11. TDD追踪

| ID | RED | GREEN门槛 |
| --- | --- | --- |
| TEST-CONTRACT-TAXONOMY-001 | schema允许未知字段/float/未排序/秘密 | `11/11 GREEN` · release/node/edge/label/crosswalk关闭schema |
| TEST-DOMAIN-TAXONOMY-001 | code换义、cycle、坏replacement、bool整数、locale漂移 | domain/property/golden tests |
| TEST-APP-TAXONOMY-PUBLISH-001 | 签名正确即发布、审批错绑、current race | trust/approval/publish strict fake与receipt |
| TEST-APP-TAXONOMY-CONSUMER-001 | 事件正文恢复、hash drift仍激活、unsupported major | consumer marker contract tests |
| TEST-DB-TAXONOMY-001 | 双ACTIVE、跨bundle FK、伪GUC/public scan | 真实PostgreSQL 18 RLS/constraint/concurrency |
| TEST-E2E-TAXONOMY-MATCH-001 | Profile/Demand current变化重写历史或不受检crosswalk匹配 | Profile→Demand→MatchRun frozen input E2E |
| TEST-SEC-TAXONOMY-001 | label/definition注入HTML或含身份/签名秘密 | Unicode/HTML/secret sentinel与CSP projection |

实施顺序：发布机器schemas与fixture/golden vectors → domain/application RED→GREEN → 独立PG catalog/migrations/RLS → consumer marker adapters → Profile/Demand/Matching compatibility E2E。正式Catalog GREEN前，Profile/Demand测试只使用明确的受信fake marker，不得用任意ID通过。

## 12. 2026-08-08 contract RED → GREEN 证据

先提交`platform/tests/contract/test_taxonomy_contracts_red.py`与secret-free canonical fixture，不创建任何机器文件。首次执行：

```bash
cd platform
PYTHONPATH=src:tests .venv/bin/python -m unittest -q \
  tests.contract.test_taxonomy_contracts_red
```

结果为`Ran 11 tests`、`19 failures`、`0 errors`。19项全部是明确的missing Taxonomy contract assertion：七份artifact逐项缺失，route/database profile、五类关闭schema、四事件和secret/property guard均未满足；没有ImportError、YAML/JSON解析、依赖或fixture错误。

随后只增加第10节列出的OpenAPI、event与五份domain schema，不实现domain/application/数据库行为。相同命令结果为`Ran 11 tests`、全部`OK`。GREEN证明关闭对象、required/type/enum、bool-as-integer拒绝、未知/秘密字段不可表示、四个exact public read、两个SYSTEM mutation、三个database access profile及四种最小事件的机器边界；fixture的canonical顺序检查不等于发布validator已实现，schema GREEN也不证明签名、approval、cycle、current replacement、receipt、RLS或consumer sync行为。

## 13. 当前实施边界

当前MVP有版本化taxonomy配置，目标Profile/Demand/Matching设计保存bundle ID；平台现有Taxonomy机器契约、框架无关Memory domain/application及独立PostgreSQL catalog/UoW/RLS均已GREEN，稳定default-deny sentinel类型仅为导入兼容而保留，不再是Memory或PostgreSQL production entry point的行为。仍没有生产consumer本地marker adapter、HTTP route或composition wiring；Profile/Demand/Matching自己的marker与跨Context一致性仍须由后续切片证明。

## 14. 2026-08-08 domain/application 第一轮 semantic RED 证据

第一轮只增加独立`desire_platform.taxonomy.domain/application/ports`：所有entity、artifact、command、authority/evidence/result均为深度不可变关闭shape；行为入口只抛稳定的`TAXONOMY_DOMAIN_BEHAVIOR_NOT_AVAILABLE`或`TAXONOMY_APPLICATION_BEHAVIOR_NOT_AVAILABLE`，没有Memory实现、PostgreSQL、HTTP、composition或测试环境分支。

测试support不是返回`None`的万能Recorder：它构造hash自洽的initial与minor-successor release，所有深层负例先重新绑定artifact descriptor以避免无关digest mismatch抢先；Publish successor预置exact predecessor/current/permanent code registry，Retire预置ACTIVE current，consumer预置空inbox/marker。copy-on-write MemoryStore/UoW支持真实lock working snapshot、13/7 checkpoint故障、selector race、COMMIT outcome unknown与新reader recovery，并在每次调用前执行pre-state一致性断言。

精确RED：

- `tests.taxonomy.test_taxonomy_domain_red`为10 methods：9 semantic failures、1 immutable pass、0 errors/skips。覆盖artifact/release/selector canonical bytes与SHA、输入顺序拒绝、NFC/UTF-8 byte/control/bool/float、code永久唯一与换义、edge self/duplicate/cycle、replacement/locale coverage、INITIAL/SemVer/derived compatibility、crosswalk cardinality/compatibility及SUPERSEDED/RETIRED终态。
- `tests.application.test_taxonomy_commands_red`为16 methods：15 semantic failures、1 immutable+secret-safe pass、0 errors/skips。覆盖SYSTEM workload/operation attestation、exact artifact/signature/trust、双独立approval、completed replay/conflict/retained keys、selector current race、Publish 13与Retire 7 checkpoint全回滚、COMMIT unknown、retire终态、consumer durable inbox/exact Catalog artifact/unsupported major/partial artifact，以及关闭event/audit/receipt/privacy。
- 两组合计26 methods、24 semantic failures、2 seam passes、0 errors/skips；失败全部来自窄捕获的exact default-deny sentinel与预期业务结果之差。Taxonomy机器契约继续11/11 GREEN；本轮不得据这些RED宣称任何Catalog业务行为已实现。

## 15. 2026-08-08 Memory GREEN 证据

GREEN严格保持第14节的10个domain与16个application方法及其业务期望。Domain实现本地JCS-compatible canonical bytes/SHA-256、NFC/UTF-8 byte/control/bool/float关闭验证、输入顺序拒绝、artifact descriptor与selector digest复算、永久code含义、edge完整性与cycle、locale/replacement、predecessor差分推导compatibility/SemVer、crosswalk exact定义绑定，以及ACTIVE→SUPERSEDED/RETIRED不可逆状态机。Application实现SYSTEM workload operation attestation、exact artifact/signature/trust/双独立approval、锁内证据/current复验、versioned retained-key receipt、关闭safe response/ETag、13/7固定checkpoint单事务、COMMIT outcome unknown只按durable完整receipt+事实恢复、retire终态、consumer exact inbox/Catalog marker及正式event validator；receipt/audit/outbox不保存raw key、credential、签名或approval正文。

GREEN过程中发现两类先前被default-deny掩盖的测试support形状问题，均在不改变业务oracle后窄修：统一domain错误helper返回`(code,field_path,reason_code)`，终态断言相应读取tuple的reason位置；pre-state guard原本每次只接受Retire/Consumer初态，现仅额外接受第一次成功产生的exact RETIRED/current-null或COMPLETED inbox+唯一exact marker durable态，使第二次终态拒绝/replay能够真正进入handler。其他状态仍由support立即拒绝，未加入lazy seed或合成结果。

精确GREEN：

- `tests.taxonomy.test_taxonomy_domain_red`：10/10 GREEN，0 failures/errors/skips；
- `tests.application.test_taxonomy_commands_red`：16/16 GREEN，0 failures/errors/skips；
- 合计26/26 GREEN。该证据本身只证明纯domain与共享copy-on-write Memory UoW语义；PostgreSQL并发、RLS与production pool disposition由独立[Taxonomy PostgreSQL 18 持久化与生产事务设计](taxonomy-postgresql.md)的12/12真实PG18证据关闭，HTTP presenter与跨Context composition仍未关闭。
