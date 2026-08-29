# Schema 与存储迁移

> 状态：阶段 0 已实现并验证；schema、纯资料迁移、SQLite 迁移、CLI、故障注入与备份恢复测试均已通过。
>
> 适用边界：当前 `mvp/` 的匿名化 JSON 与本地 SQLite；不是目标平台 PostgreSQL 的迁移方案。

本文收口[输入契约](/architecture/input-contracts-and-imports.md#版本与迁移方向)留下的版本化缺口，并落实 [ADR-0001](/decisions/0001-platform-scope-and-delivery.md#兼容与迁移原则) 与[平台 TDD 规范](/development/platform-tdd.md#13-迁移兼容与差分测试)。已实现的结果是：所有新资料都显式声明 v1；旧库只经可预检、可备份、单事务的命令迁移；推荐历史不因资料升级而改变。

## 1. 目标与非目标

本切片必须交付：

- demand、creator、outcome 根对象的显式 `schema_version`；
- 确定、无副作用的 `v0 -> v1` 资料迁移器；
- 正式、单调、带校验和的 SQLite migration registry；
- `migrate status`、`--dry-run` 与 `--apply` CLI 契约；
- 迁移前备份、失败回滚、重复执行和恢复验收；
- 旧推荐输入、结果和预算 JSON 的字节级不变证明；
- REQ → DESIGN → TEST → CODE 追踪。

本切片不增加账户、网络 API、身份资料、自动删除或 PostgreSQL；不把旧推荐升级成新格式；不支持任意版本图，只支持隐式 v0 到 v1。未来 `v1 -> v2` 必须新增迁移函数和 migration，不可修改已发布的 v0→v1 逻辑。

## 2. 四条版本轴

| 版本轴 | 事实来源 | 用途 | 不得混用 |
| --- | --- | --- | --- |
| 资料 schema | JSON 根级 `schema_version` | demand、creator、outcome 的结构 | 不是匹配规则版本 |
| SQLite schema | `schema_migrations.version` | 表、列、索引、触发器 | 不是资料版本 |
| 推荐快照格式 | `recommendation_snapshot_manifests.snapshot_schema_version` | 选择 v0/v1 只读解码器 | 不触发资料回写 |
| 规则复合版本 | `recommendations.rule_version` | 复算匹配与预算 | 不表示数据库结构 |

所有版本都是整数或已有的显式规则字符串，不从应用版本、文件名或字段形状猜测。`true` 在 JSON 中虽可被 Python 当作整数，也不是合法版本。

## 3. v1 资料契约

### 3.1 根对象

v1 demand、creator、outcome 每条记录都必须在根级包含：

```json
{
  "schema_version": 1,
  "id": "demand-demo-001"
}
```

上例只展示版本位置，不是完整合法 demand。机器契约发布在：

- `mvp/schemas/demand-v1.schema.json`；
- `mvp/schemas/creator-v1.schema.json`；
- `mvp/schemas/outcome-v1.schema.json`。

schema 要求 `schema_version` 为 JSON integer 且 `const: 1`，并与 required、unique/min-items、容器与标量 type、数值 range、enum、真实日历 date、隐私安全 ID、受控外部引用和关闭的安全事件最小投影共同执行。结构化对象默认拒绝未知字段；运行时 `desire_mvp.schema`、Repository 当前读写边界与迁移目标共享这份静态 contract，动态 taxonomy、reason code 和其他会随规则版本变化的业务语义仍由当前 `ConfigBundle` 校验。未知键名在对外路径中固定为 `<unknown-field>`，不回显用户控制的属性名。

静态 contract 也包含不依赖可变配置的跨字段不变量：demand 的付款百分比合计、日期先后与预算上下界，creator 技能标签唯一，以及 outcome 的完成/付款/失败组合、参与者数组基数和计划/实际日期先后。它们在纯 v0→v1 结果、Repository 当前读写和普通 validator 上一致执行；迁移不能通过“只加版本号”绕过业务上固定的结构矛盾。

切换规则如下：

- 新文件导入只接受显式 v1；缺失、`0`、布尔值、字符串或未知正整数都以 `UNSUPPORTED_SCHEMA_VERSION` 拒绝；
- 省略版本仅表示历史隐式 v0，且只允许进入迁移器或历史快照解码器；常规 `import` 不再接受；
- Repository 写当前资料时，同时保存 `payload_schema_version = 1`，并核对它等于 JSON 根值；
- Repository 读当前资料时遇到缺失、未知或列/JSON 不一致，安全失败，不在 `get_entity` 中补字段。

### 3.2 v0→v1 的唯一转换

迁移函数以深拷贝输入和显式 resolution 为参数，不读取数据库、时钟、网络或当前配置，不修改调用者对象；同一输入产生相同的规范 JSON 和变更清单。

| 记录 | v0 识别 | v1 转换 | 拒绝条件 |
| --- | --- | --- | --- |
| demand | 根级无 `schema_version` | 加 `schema_version: 1`；其余字段原义保留 | `status=closed` 无显式 resolution；v0 结构本已损坏 |
| creator | 根级无 `schema_version` | 加版本；`withdrawn` 确定映射为 `inactive`，记录 `WITHDRAWN_TO_INACTIVE` | v0 结构本已损坏 |
| outcome | 根级无 `schema_version` | 只加版本 | v0 结构本已损坏 |
| 任一 v1 | 根级整数 `1` | identity，不重新序列化、不生成迁移审计 | v1 校验失败 |
| 任一未知版本 | 根级存在但不是整数 `1` | 不转换 | `UNSUPPORTED_SCHEMA_VERSION` |

除上述两项外，迁移器不填默认值、不删除未知字段、不按“今天”的 taxonomy 改标签，也不修复无效数据。迁移器会对每个预计目标执行完整静态 v1 contract；仅仅成功添加 `schema_version` 不能让缺必填、未知字段、错误类型/范围/枚举/日期/ID 的 legacy payload 通过，计划必须以 blocker 阻断整个 apply。损坏资料必须先走单独、可审计的人工更正，不能把猜测藏在迁移中。

`closed` 无法可靠区分“已建立项目”与“未成交关闭”，因此 resolution 文件必须逐条给出：

```json
{
  "schema_version": 1,
  "demand_status_resolutions": [
    {
      "demand_id": "demand-demo-001",
      "from": "closed",
      "to": "agreed",
      "reason_code": "PROJECT_ESTABLISHED",
      "evidence_ref": "external://migration-review-001"
    }
  ]
}
```

`to` 只能是 `agreed | cancelled`；相应原因只能是 `PROJECT_ESTABLISHED | NO_PROJECT_ESTABLISHED | OPERATOR_CORRECTION`。每个 closed demand 恰好一条 resolution；重复、缺失、未使用、目标/原因矛盾或 evidence ref 为空都会阻断整库迁移。文件只保存受控引用，不保存合同、联系人或证据正文。

resolution 文件本身是关闭文档：根级只能有整数 `schema_version: 1` 与数组 `demand_status_resolutions`；每项必须是对象，且只能有五个字符串字段 `demand_id/from/to/reason_code/evidence_ref`。`from` 固定为 `closed`，`PROJECT_ESTABLISHED` 只配 `agreed`，`NO_PROJECT_ESTABLISHED` 只配 `cancelled`，`evidence_ref` 必须通过受控外部引用语法。对象、数组或标量类型错误都统一为脱敏 `INVALID_DEMAND_STATUS_RESOLUTION`，不得泄漏原值或 Python 异常。

### 3.3 行元数据身份

legacy 表的检索列也属于迁移源事实。plan 在转换前核对：entity 行的 kind/id/pilot 与 payload 身份一致（creator 的行 pilot 必须为 `NULL`），outcome 行的 project/pilot/demand/creator IDs 与 payload 一致。任何漂移只记录 `LEGACY_ROW_METADATA_MISMATCH` blocker；不选择某一侧、不覆盖、不生成审计。迁移后的 Repository 对 current 行继续执行相同身份核对，详见[输入契约](/architecture/input-contracts-and-imports.md#sqlite-行元数据与-payload-身份)。

## 4. 支持的 SQLite 起点与 initialize

迁移器只接受三种可证明起点：

1. 空目录或空数据库；
2. `legacy-v0a`：现有四张业务表，但 `decisions` 尚无 `participant_responses_json`；
3. `legacy-v0b`：当前 `SCHEMA` 及该列，但没有 `schema_migrations`。

legacy 识别不是按名称/列集合拼出的近似判断：实现把实际全部受管 `sqlite_master` table/index 对象与内存中执行冻结 v0a/v0b DDL 得到的规范对象逐项比较。类型、主键、CHECK/DEFAULT/FOREIGN KEY、唯一/部分/降序索引、索引列顺序、额外或缺失对象任一漂移都返回 `UNRECOGNIZED_LEGACY_SCHEMA`，不得“尽力升级”。v0a 的缺列在正式 migration 中以 `NOT NULL DEFAULT '[]'` 补齐，并纳入测试；现有 `Repository.initialize()` 中的临时 `ALTER TABLE` 随实现切片移除。

切换后的 `initialize()` 行为：

- 空库：在一个事务内直接 bootstrap 完整 v3 schema，再写入 1–3 的 registry receipt；这些 receipt 的 `plan_id` 固定为 `bootstrap-empty-v3`。完整 v3 仍包含运行/审计表，但这不是 legacy 资料迁移，所以不写 `migration_runs` 或 `payload_migration_audit` 记录，也不创建备份；重复 initialize 只做校验；
- 当前库：校验 migration 连续性、descriptor checksum 与 receipt chain，并把受管 table 的规范 CREATE SQL 和 index/trigger 的所属表及规范 SQL 与当前 `SCHEMA` 参考库逐一核对；同名/同列但丢失 CHECK、主键、外键、DEFAULT 或触发器语义仍然失败。受管 table 必须精确，且全库非 SQLite 内建 index/trigger 名称集合必须与当前定义完全相等；未知 trigger 即使声称用于诊断，也可能吞掉或删除写入，因此一律 `MIGRATION_HISTORY_INVALID`。registry receipt 不能单独证明真实 DDL 仍然存在；
- fingerprinted legacy：返回稳定错误 `MIGRATION_REQUIRED`，不创建表、不加列、不改 payload，并提示先运行 dry-run；
- checksum 漂移、版本缺口或未知的未来版本：返回 `MIGRATION_HISTORY_INVALID`，禁止所有写命令；
- `list`、`explain`、`report` 在迁移窗口可经冻结的 legacy 只读适配器读取，不能借此写回；其他业务命令在迁移完成前失败。

版本 1 或 2 的部分数据库不是可继续执行下一步的公开 baseline，而是完整性无效状态；本实现不会从其中恢复或续跑。未来若要支持完整的较低版本数据库，必须先冻结该 baseline 的结构指纹，再新增独立迁移设计和测试，不能复用当前 legacy 入口。

`migrate` 自己不得调用会写库的 `initialize()`。

## 5. 目标 SQLite 结构

### 5.1 Migration registry

`schema_migrations` 是 SQLite 结构版本的唯一事实来源；不把 `PRAGMA user_version` 当作第二份权威状态。

```sql
CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY CHECK (version > 0),
  name TEXT NOT NULL UNIQUE,
  checksum_sha256 TEXT NOT NULL CHECK (length(checksum_sha256) = 64),
  app_version TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  applied_at TEXT NOT NULL
);
```

已应用版本必须从 1 连续到当前版本 3。checksum 覆盖不可变 migration descriptor（SQL、数据转换版本和执行顺序）；运行时代码与已存 checksum 不符就停止，修正只能追加新版本。Repository 还独立核对受管 table 的规范 CREATE SQL、index/trigger 精确定义和 registry/receipt chain；registry checksum 正确但约束漂移、同名错误对象或伪造 receipt 存在时同样以 `MIGRATION_HISTORY_INVALID` 失败。

本切片固定为：

1. `0001_bootstrap_and_expand`：对 v0a/v0b 建立 registry、运行审计和扩展结构，补 v0a 缺列；fresh database 走前述直接 bootstrap，不执行 legacy backfill；
2. `0002_backfill_payload_v1`：迁移当前 entities/outcomes，登记推荐快照摘要与资料迁移审计；
3. `0003_contract_v1_and_history`：重建当前资料表为 v1 约束，增加推荐与迁移历史不可变触发器。

三步由一次 `--apply` 的同一个外层事务执行。阶段拆分用于测试和未来兼容推理，不允许用户停在半完成状态。

### 5.2 当前资料与审计

`entities` 和 `outcomes` 增加 `payload_schema_version INTEGER NOT NULL CHECK(payload_schema_version = 1)`；其余主键和业务列保持。应用层在每次写入前核对 JSON 根版本。

另建立：

```sql
CREATE TABLE migration_runs (
  plan_id TEXT PRIMARY KEY,
  source_database_version INTEGER NOT NULL,
  target_database_version INTEGER NOT NULL,
  source_fingerprint TEXT NOT NULL,
  target_fingerprint TEXT NOT NULL,
  resolution_sha256 TEXT,
  backup_path TEXT NOT NULL,
  backup_sha256 TEXT NOT NULL,
  summary_json TEXT NOT NULL,
  applied_at TEXT NOT NULL
);

CREATE TABLE payload_migration_audit (
  plan_id TEXT NOT NULL,
  record_type TEXT NOT NULL,
  record_key TEXT NOT NULL,
  from_version INTEGER NOT NULL,
  to_version INTEGER NOT NULL,
  before_sha256 TEXT NOT NULL,
  after_sha256 TEXT NOT NULL,
  change_codes_json TEXT NOT NULL,
  resolution_code TEXT,
  resolution_ref TEXT,
  PRIMARY KEY (plan_id, record_type, record_key),
  FOREIGN KEY (plan_id) REFERENCES migration_runs(plan_id)
);
```

审计只存 ID、摘要、固定 change/reason code 和外部引用，不复制完整 payload 或证据正文。

### 5.3 Receipt chain 与 append-once

切换事务先插入唯一 `migration_runs` 父 receipt 和其 `payload_migration_audit` 子行，最后写入三条同一 `plan_id` 的 registry。current contract 随后要求二者满足以下封闭关系：

- fresh bootstrap 的三条 registry 都使用 `bootstrap-empty-v3`，且 `migration_runs`/audit 必须为空；
- legacy cutover 的 registry 只能引用一个 plan，必须恰有一个同 plan 的 run；audit 只能引用该 plan；版本轴、摘要格式、备份路径和固定 summary 字段都必须有效；
- receipt 中的 `target_fingerprint` 是切换 commit 时刻的证据，不是 current 业务表的永久 checksum。合法 v1 写入会改变 live fingerprint，但不得使 `migrate status --plan-id` 或同 plan 幂等重试失效。

受管触发器把这组历史变成 append-once：registry 达到当前三版后禁止继续 insert，并始终禁止 update/delete；一旦 registry 存在，run/audit 禁止补写，且二者始终禁止 update/delete。触发器本身的所属表与规范 SQL 也是 current contract 的一部分；只保留同名空触发器不能通过校验。未来追加数据库版本必须先设计新的受控过渡，不能临时删除这些保护。

## 6. 推荐历史绝不迁移

已有 `recommendations.input_snapshot_json`、`result_json`、`budget_json` 是当时决策事实。v0→v1 迁移对这三列执行 **零 UPDATE、零 DELETE、零重新序列化**；即使快照内 demand/creator 是隐式 v0，也保持原字节。

迁移前后分别对每列原始 TEXT 的 UTF-8 字节取 SHA-256，并建立：

```sql
CREATE TABLE recommendation_snapshot_manifests (
  recommendation_id INTEGER PRIMARY KEY,
  snapshot_schema_version INTEGER NOT NULL CHECK (snapshot_schema_version IN (0, 1)),
  input_sha256 TEXT NOT NULL,
  result_sha256 TEXT NOT NULL,
  budget_sha256 TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  FOREIGN KEY (recommendation_id) REFERENCES recommendations(id)
);
```

既有行登记为 snapshot v0；新推荐使用 snapshot v1，`input_snapshot_json` 根级也包含 `schema_version: 1`，内部 demand/creator 都是 v1。新推荐及 manifest 必须在一个事务内插入。

数据库触发器拒绝普通 `UPDATE/DELETE recommendations` 以及 manifest 的修改/删除。当前 MVP 的受控删除粒度是整库或完整批次，不提供逐行绕过触发器的应用后门；未来若需要法律删除或逐行保留执行器，必须另行设计并评审 `RetentionRunner`，不能把它伪装成 schema migration。

只有经完整冻结 `sqlite_master` DDL 识别的 legacy-v0a/v0b 可在没有 manifest 时进入 legacy 只读分支；这个例外不会依据 payload 形状猜测版本，也不会写回。带 current registry 的数据库强制每条推荐都有 manifest，v0/v1 分支只返回内存投影；manifest 缺失、行数不等、摘要不符或未知版本均以 `HISTORY_INTEGRITY_ERROR` 停止。

## 7. CLI 契约

全局 `--data-dir` 仍写在子命令前。实现新增：

```bash
mvp --data-dir <dir> migrate status

mvp --data-dir <dir> migrate status --plan-id <plan-id>

mvp --data-dir <dir> migrate --payload-schema 1 --dry-run \
  --plan-out <secure-plan.json> [--resolutions <secure-resolutions.json>]

mvp --data-dir <dir> migrate --payload-schema 1 --apply \
  --plan <secure-plan.json> \
  --backup-dir <controlled-backup-dir> \
  [--resolutions <secure-resolutions.json>]
```

`--payload-schema 1` 是唯一公开的目标参数；隐藏的 `--to 1` 只保留给既有脚本作兼容别名，两者不能同时传入，也不能把它解释成数据库版本。status 与 plan 输出同时声明 `target_database_version: 3` 和 `target_payload_schema_version: 1`，避免两条版本轴混淆。

`--dry-run` 与 `--apply` 互斥。`status` 和 plan 都以 SQLite read-only 模式打开一次连接并显式 `BEGIN`：状态分类、legacy/current DDL 校验、current receipt 查询，以及 plan 的源指纹、业务资料和推荐摘要分别在各自单一一致快照内完成；legacy plan 还在该快照内核对行元数据身份。不能先用一个连接判断版本、再用另一个连接读取已变化的库。它们绝不调用 initialize，也不改数据库、旁路日志或样例。对 legacy，dry-run 唯一允许的写入是调用者显式指定、必须原先不存在的 plan 文件；若源库已经是完整 v3/v1，则 stdout 返回 `status: no_changes`，即使传了 `--plan-out` 也不创建 plan 文件。stdout 只输出计数、版本、固定错误码、plan ID 和摘要，不输出 payload、私密金额、resolution evidence 或不合规 legacy ID。

计划根对象必须且只能包含：

```text
plan_format_version, plan_id, source_database_version,
target_database_version, target_payload_schema_version,
source_fingerprint, resolution_sha256, migrations, counts, blockers,
recommendation_history_sha256, target_payload_sha256
```

它只保存版本、业务事实逻辑指纹、migration 名称/checksum、resolution 摘要、记录计数、推荐三列摘要集合的总摘要、预计目标资料摘要和 blockers，不包含完整资料。plan parser 是关闭且强类型的：根字段集合必须完全相等；版本只能是当前允许的整数轴（布尔值不算整数）；migration/blocker 每项字段集合精确；descriptor 列表必须等于当前冻结列表；counts 必须恰含固定键且为非负整数；blocker code 大写、唯一且排序，count 为正整数；所有摘要为 64 位小写十六进制。未知字段、被静默过滤的非对象、字符串计数或“重新算过 hash”的语义伪造 plan 都拒绝。

`plan_id` 是除 `plan_id` 自身外**全部持久化计划字段**的 canonical JSON SHA-256；生成时间不参与 ID。计划对象在写文件前、从文件读回时和进入 apply 时都会重算并比较该摘要；apply 还从当前同快照事实重新生成语义 plan。因此保留旧 ID 篡改字段，或篡改后自行重算 ID，都以 `INVALID_MIGRATION_PLAN`/`STALE_MIGRATION_PLAN` 失败。

resolution 摘要是经过关闭结构和受控语义校验后的 resolution 数组 canonical JSON SHA-256。apply 必须取得同一代码版本生成的零 blocker plan，并重新计算所有输入与转换，不信任 plan 中的计数或结论：plan 的 resolution digest 非空时必须再次提供完全相同的 resolutions；digest 为空时拒绝额外 resolutions；缺失、增加、删除、重排、类型变化或内容修改都不能绕过计划绑定。重算出的完整 `plan_id`、数据库指纹、migration checksum 或 resolution 摘要任一变化都返回 `STALE_MIGRATION_PLAN`；必须重新 dry-run，不能用 `--force` 绕过。若源库已完整 current，apply 仍重算 current plan 并确认 ID 相等后才返回 `no_changes`，不创建锁、备份、receipt 或任何数据库写入。

退出语义：成功、无须迁移或同一 plan 已完成为 `0`；可预期的 schema、数据、plan、resolution、锁、备份或完整性错误为 `2`；提交结果无法判定为 `3 / MIGRATION_RECOVERY_REQUIRED`，禁止自动重试。操作者以 `migrate status --plan-id <plan-id>` 恢复判断：只有 current managed DDL 与不可变 registry/receipt chain 在同一快照内有效且 receipt 链接该 plan 时返回 `applied`。status 刻意不要求今天的可变业务 live fingerprint 等于 cutover receipt 的目标指纹；否则任何合法迁移后写入都会伪装成迁移失败。

## 8. 指纹、事务与幂等

逻辑指纹由两部分构成：受管 `sqlite_master` 对象的规范描述，以及四张现有业务表稳定排序后的行元数据/原始 JSON TEXT 摘要。migration 的时间戳、运行审计和备份路径不参与计划的源指纹。这样能检测计划后并发写入，又不依赖 SQLite 文件页布局。指纹不能替代契约断言：legacy 另作 exact frozen DDL 与行元数据身份核对；目标另作 manifest 数量/逐行摘要、registry/receipt chain，以及 current 受管 table/index/trigger 精确定义核对。

apply 固定顺序：

1. 取得 data-dir 的独占迁移锁；第二个进程超时后返回 `MIGRATION_BUSY`；
2. 打开专用写连接，启用 foreign keys，以 `BEGIN IMMEDIATE` 阻止新写入；
3. 在同一只读快照重算源指纹、行元数据身份、plan、resolution 与 migration checksum；
4. 在任何 DDL/DML 前，由独立的 read-only 源连接调用 SQLite backup API，向一个全新文件复制写事务所锁定的源库；不得在持有 `BEGIN IMMEDIATE` 的同一写连接上调用 backup，以免连接自锁；
5. 对备份运行 `PRAGMA integrity_check`，并证明其逻辑指纹等于源指纹；
6. 在同一外层事务逐条执行 migration；不得使用可能隐式提交的 `executescript`；
7. 重算每个推荐 blob 摘要，断言与迁移前完全相同；
8. commit 前运行 manifest 行数/摘要、`foreign_key_check` 与 `integrity_check`；后续 Repository/status 读取还会核对 registry checksum 与 current 结构及 index/trigger 精确定义；
9. 资料转换时先在内存生成 audit rows；在事务内先插入父行 `migration_runs`，再写 `payload_migration_audit`，最后登记 `schema_migrations`。这个顺序既满足外键，也让 append-once 触发器在 registry 完成后封闭 run/audit 的补写窗口；
10. commit 后、返回成功前，关闭写连接并重新打开 read-only 连接，再核对 current contract、该 `plan_id` 的 receipt、receipt 中的源/目标指纹和**此刻**的目标逻辑指纹；提交后的并发写入、receipt 缺失、指纹竞态或此阶段任何无法判定的错误都转为 `MIGRATION_RECOVERY_REQUIRED`，绝不误报成功。这个即时确认不等于要求未来 status 永远匹配同一 live 指纹。

任何 commit 前失败都回滚三步 migration 和全部审计行；备份作为恢复证据保留。当前数据量采用单一离线事务，不引入部分 backfill checkpoint。

幂等规则：

- 相同 plan 在成功后重放，先验证 current registry/受管结构，再查询 `migration_runs.plan_id` receipt；命中即返回 `already_applied`，不新建备份、不改时间戳，也不会先拿已变化的当前业务指纹去与 legacy 源指纹比较；
- 切换后的合法 v1 业务写入可以改变 entities/outcomes/recommendations 等 live 事实；只要受管 DDL、append-once registry/receipt/audit 链仍有效，原 plan 的 status 仍为 `applied`，幂等重试仍为 `already_applied`；
- 已是完整 v3/v1 的库由 `migrate status` 报告 `current`；dry-run 返回 `no_changes` 且不写 plan，apply 返回 `no_changes` 且不取迁移锁、不创建备份/receipt、不改数据库；
- 混合 v0/v1 当前资料可以计划：合法 v1 保持原字节，仅 v0 转换；
- migration 版本缺口、旧 checksum 漂移、未知未来版本、版本 1/2 的 partial 数据库或只有部分 contract 对象都不是“可续跑”，而是完整性阻断。

## 9. 故障语义

| 故障点 | 对外结果 | 数据结果 | 下一步 |
| --- | --- | --- | --- |
| 未知 legacy schema、坏 JSON、未知版本、无效 v1 目标 contract、缺 resolution | `2` + 稳定 blocker | 源库未写 | 修复源问题后重新 dry-run |
| legacy 行元数据与 payload 身份不一致 | `2` + `LEGACY_ROW_METADATA_MISMATCH` | 源库未写，不猜测权威侧 | 人工核实并走独立更正后重做 dry-run |
| plan/resolution 未知字段、错误容器/标量、语义或摘要伪造 | `2` + `INVALID_MIGRATION_PLAN` / `INVALID_DEMAND_STATUS_RESOLUTION` | 不写 plan、备份或数据库 | 重新生成关闭格式的输入，不复用错误文件 |
| 文件不是合法 SQLite 或 SQLite 元数据损坏 | `2 / MIGRATION_HISTORY_INVALID` | 原文件保持原字节 | 隔离文件并从已验证备份恢复；不依赖原始驱动异常 |
| plan 后业务写入 | `STALE_MIGRATION_PLAN` | 源库未写 | 重新生成 plan |
| 迁移锁被占用 | `MIGRATION_BUSY` | 源库未写 | 等当前进程结束，不并发 apply |
| 备份创建、权限、空间或校验失败 | `BACKUP_FAILED` | 尚未执行 migration | 修复备份介质 |
| DDL、backfill、触发器或最终断言失败 | `MIGRATION_ROLLED_BACK` | 整个数据库事务回滚 | 保留备份与脱敏失败摘要 |
| 进程在 commit 前终止 | 下次状态为 legacy | SQLite 回滚 journal/WAL | 用原 plan 重试前先 status |
| commit 已成功但响应丢失，或提交后只读复核遇到并发指纹变化 | 首次返回 `3 / MIGRATION_RECOVERY_REQUIRED` | 可能已完整成功，也可能已有后续写入 | `migrate status --plan-id`；receipt 存在且 current registry/结构完整时视为 `applied`，否则人工接管 |
| status 无有效 receipt chain，或 current 精确 DDL/append-once 触发器损坏 | `MIGRATION_HISTORY_INVALID` | 不自动假定源/目标状态 | 停止业务命令，从备份恢复到隔离位置并人工接管 |
| 推荐摘要变化 | `HISTORY_INTEGRITY_ERROR` | commit 前回滚 | 不允许忽略或重新基线化摘要 |

错误输出不得包含原始 SQL/SQLite 驱动异常、完整 payload、私密金额或 resolution 正文；即使文件是任意字节而不是数据库，status 也只返回稳定 `MIGRATION_HISTORY_INVALID`，不输出 `DatabaseError`、traceback 或文件内容。调试细节写入受控本地日志也必须脱敏。

## 10. 备份、恢复与保留

`--backup-dir` 对 apply 是必填项，必须已存在、可写且位于 live data-dir 之外；若该目录自身或任一祖先含 `.git`，即处于 Git worktree/仓库内，也以 `BACKUP_FAILED` 拒绝，不能把真实备份落入版本控制范围。备份与 manifest 使用 `O_EXCL` exclusive-create，文件权限收紧为 `0600`，不覆盖同名文件，并在迁移前通过 `integrity_check`、源逻辑指纹和数据库 SHA-256 验证。相邻 manifest 记录 plan ID、源指纹、数据库 SHA-256 和应用版本；数据库内的成功 run 也记录路径与摘要。

backup 最终路径以 `O_EXCL` 打开后，descriptor 一直保留到成功返回。SQLite backup API 先写权限为 `0700` 的私有 staging 目录，在那里完成 `integrity_check`、源指纹和流式 SHA-256；随后只经保留 descriptor 的 duplicate fd 把 staging 内容复制到最终 inode，文件 `fsync` 后核对 descriptor 摘要及路径 `(st_dev, st_ino)`，绝不按最终路径重新打开写入。这样即使路径在中途被换成外来 SQLite，外来 inode 也不会被覆盖。manifest 同样保留 exclusive descriptor、写入后 `fsync` 并核对路径身份；两个目录项都完成后还要 `fsync` 备份目录。

异常清理只在路径仍是本次 descriptor 对应的普通 inode 时 unlink；另一个进程赢得创建竞态，或本次创建后路径被替换，外来文件都必须保留。restore 也保留目标 `O_EXCL` descriptor，经 duplicate fd 复制并 `fsync`，用 descriptor hash 和路径 inode 双重核对；失败时只清理原目标 inode。backup/restore 的数据库 SHA-256 以固定大小块流式读取，不能用整文件 `read_bytes()` 把数据库载入内存；文件大小不改变摘要语义。

这些检查证明“本次迁移创建了一份未覆盖、权限受限且内容可验证的操作备份”，不证明底层磁盘、卷或传输已经加密。生产环境是否满足静态加密、密钥轮换和离机保留，必须由部署与运营证据另行证明；CLI 不会把一个可写目录误报成加密介质。

本迁移的 RPO 设计目标是迁移锁取得后的 **0 个已提交事实**：备份必须与计划验证的源指纹一致。当前实现是单事务离线迁移，没有自动数据量阈值、在线 backfill 或 RTO 承诺；大库在执行前必须另做容量、时长和分批设计，不能从现有 CLI 行为推断可接受窗口。

恢复不直接覆盖 live 文件：先要求 manifest 恰含 `plan_id/source_fingerprint/database_sha256/app_version`，再校验备份 SHA-256、`integrity_check` 和源指纹，以 exclusive-create 复制到一个原先不存在的隔离目录；复制完成后必须对副本再次核对 descriptor SHA-256、路径 inode、`integrity_check` 和逻辑指纹，并在成功返回前 `fsync` 隔离目录，不能把“源备份通过”当作“复制结果通过”。恢复失败时只删除仍属于本次 descriptor 的副本 inode 和本次创建的空目录；若目标文件或目录调用前已存在，或目标路径中途被替换，必须原样保留并返回完整性错误。副本通过后再运行 legacy 只读命令，停止写入，将故障库移动到隔离保留名，把已验证副本切换为 live，随后重新 dry-run/apply。迁移测试必须自动把真实生成的备份恢复到临时目录并跑核心读取冒烟，而不只检查文件存在。

成功备份至少保留到 v1 全量测试、CLI E2E 和一次恢复演练通过；之后按[数据、安全与隐私](/architecture/data-and-security.md#数据保留与删除)执行受控过期，迁移器永不自动删除备份。备份含 B 层历史资料，不得提交仓库或附在 CI 日志。

## 11. 切换与回退

实现发布顺序固定为：先发布能读 legacy、能生成迁移计划但对 legacy 禁写的版本；运营 dry-run 并解决 blocker；apply；验证；再允许 v1 写入。旧应用虽可能忽略 JSON 新字段，却不知道 `payload_schema_version`、manifest 和不可变触发器，因此 apply 后不得回滚到旧二进制。应用回退目标必须是“已包含 v1 Repository 的上一构建”，不是当前 v0 构建。

若 v1 验证失败，先停止写入，再按备份恢复流程回到完整 v0 库；不编写会删除审计或倒改快照的 down migration。已在 v1 接受新写入后，v0 备份不再是无损回退点，此时只能前向修复或经独立、带数据导出的回退设计处理。

## 12. TDD 验收证据

本切片先提交了会因模块、parser 与 legacy 写门缺失而失败的测试，再依序实现纯函数、Repository gate、迁移事务、CLI 和恢复路径。现有自动化证据覆盖：

1. `test_schema_versions.py`：严格版本、关闭字段、错误脱敏、current 读 fail-closed、受控引用、安全事件与 `test_optional_funding_reference_empty_missing_and_null_semantics` 的可选证据语义；
2. `test_contract_and_storage_invariants.py`：`test_demand_contract_rejects_fixed_cross_field_contradictions`、`test_creator_contract_rejects_duplicate_skill_tags`、`test_outcome_contract_rejects_fixed_state_and_cardinality_contradictions` 锁定固定静态不变量；`test_legacy_preflight_rejects_row_metadata_payload_mismatches` 与 `test_current_repository_reads_reject_row_metadata_payload_mismatches` 锁定行/payload 身份；
3. `test_migrations.py`：纯 v0→v1、withdrawn 映射、v1 identity 与未知版本；`test_closed_demand_requires_exactly_one_resolution`、`test_closed_resolution_targets_reasons_and_evidence_are_controlled`、`test_unused_resolution_blocks_migration` 锁定 controlled resolutions；
4. `test_repository_migrations.py`：bootstrap、v0a/v0b、推荐字节不变、stale/rollback/幂等；`test_req_mig_005_rejects_rehashed_semantically_forged_current_plan` 与 `test_req_mig_005_plan_parser_rejects_nonexact_document_shapes` 锁定关闭 plan；`test_req_mig_003_rejects_same_named_legacy_index_on_wrong_columns`、`test_req_mig_003_rejects_same_named_legacy_definition_drift`、`test_req_mig_003_rejects_current_table_with_columns_but_no_constraints`、`test_req_mig_003_current_plan_validates_the_managed_contract`、`test_req_mig_003_unknown_managed_table_trigger_is_rejected` 锁定 exact DDL 与未知 trigger 拒绝；
5. `test_cli_migrations.py`：canonical flag、status/dry-run/apply、current no-change、legacy gate、计划权限、阻断脱敏、stale 与 malformed SQLite；`test_req_mig_005_malformed_resolution_has_stable_safe_exit` 锁定 resolution 类型错误；
6. `test_migration_recovery.py`：备份/恢复、锁和 commit-unknown；`test_req_mig_007_backup_create_race_never_deletes_foreign_file`、`test_req_mig_007_backup_cleanup_preserves_replacement_inode`、`test_req_mig_007_backup_never_writes_a_replacement_inode`、`test_req_mig_007_restore_cleanup_preserves_replacement_inode`、`test_req_mig_007_backup_hashing_is_streaming` 锁定 descriptor/inode 所有权、禁止写替换 inode 与流式摘要；`test_req_mig_008_fresh_database_rejects_forged_applied_receipt`、`test_req_mig_006_receipt_survives_legitimate_postmigration_writes`、`test_req_mig_004_migration_history_is_append_once_after_cutover` 锁定 receipt chain、live 写入与 append-once；
7. `test_migration_e2e.py`：legacy→v3/v1 切换后继续 import/list/match，并生成 v1 推荐快照。

本切片是当前 MVP SQLite 兼容边界，因此 PostgreSQL、HTTP 授权和无障碍测试有理由不适用；它们不证明目标平台持久化。CLI 的结构化输出、隐私脱敏、`0600` 文件权限、推荐历史和恢复均已有自动化保护。

## 13. REQ → DESIGN → TEST → CODE

以下路径、测试与符号对应当前实现；全量 `unittest`、文档校验与恢复测试通过后均标为 `verified`。

| REQ | DESIGN | 验收 | TEST | CODE | 证据/状态 |
| --- | --- | --- | --- | --- | --- |
| `REQ-MIG-001` | `DES-MIG-001` · 本文“v1 资料契约” | static contract 含固定跨字段不变量，并在 validator、Repository 和迁移目标一致执行 | `TEST-UNIT-MIG-001` · `test_contract_and_storage_invariants.py::test_demand_contract_rejects_fixed_cross_field_contradictions`、`test_creator_contract_rejects_duplicate_skill_tags`、`test_outcome_contract_rejects_fixed_state_and_cardinality_contradictions`；`test_repository_migrations.py::test_req_mig_001_blocks_legacy_payload_invalid_under_v1_contract`；`test_schema_versions.py::test_optional_funding_reference_empty_missing_and_null_semantics` | `CODE-MIG-001` · `schema.validate_payload_contract`、`_fixed_invariant_violations`、`is_controlled_reference`；`mvp/schemas/*-v1.schema.json` | `verified` |
| `REQ-MIG-002` | `DES-MIG-002` · 本文“v0→v1 的唯一转换” | 转换纯且确定；closed resolution 是关闭、受控且与 plan 绑定的输入 | `TEST-UNIT-MIG-002` · `test_migrations.py::test_closed_demand_requires_exactly_one_resolution`、`test_closed_resolution_targets_reasons_and_evidence_are_controlled`、`test_unused_resolution_blocks_migration`、`test_v1_is_identity_and_does_not_generate_migration_audit`；`test_cli_migrations.py::test_req_mig_005_malformed_resolution_has_stable_safe_exit` | `CODE-MIG-002` · `migrate_record_v0_to_v1`、`_validate_resolution_shape`、`cli._load_migration_resolutions` | `verified` |
| `REQ-MIG-003` | `DES-MIG-003` · 本文“支持的 SQLite 起点与 initialize” | legacy 全对象精确 DDL；current 受管 table 与全量 index/trigger 集合精确定义 | `TEST-DB-MIG-003` · `test_repository_migrations.py::test_req_mig_003_rejects_same_named_legacy_index_on_wrong_columns`、`test_req_mig_003_rejects_same_named_legacy_definition_drift`、`test_req_mig_003_rejects_current_table_with_columns_but_no_constraints`、`test_req_mig_003_current_plan_validates_the_managed_contract`、`test_req_mig_003_unknown_managed_table_trigger_is_rejected` | `CODE-MIG-003` · `migration_support.frozen_legacy_variant`、`Repository._validate_current_contract`、`canonical_table_sql` | `verified` |
| `REQ-MIG-004` | `DES-MIG-004` · 本文“Receipt chain 与 append-once”及“推荐历史绝不迁移” | 推荐字节不变；registry/run/audit 切换后不可补写、改写或删除 | `TEST-DB-MIG-004` · `test_repository_migrations.py::test_recommendation_history_is_byte_immutable`、`test_req_mig_004_rejects_same_named_but_wrong_managed_trigger`；`test_migration_recovery.py::test_req_mig_004_migration_history_is_append_once_after_cutover` | `CODE-MIG-004` · `MIGRATION_HISTORY_TRIGGER_DEFINITIONS`、`Repository._validate_migration_receipt_chain`、`MigrationRunner._apply_0003` | `verified` |
| `REQ-MIG-005` | `DES-MIG-005` · 本文“CLI 契约” | status/plan 同快照；plan parser 关闭强类型；摘要与语义双重重算 | `TEST-CLI-MIG-005` · `test_cli_migrations.py::test_canonical_payload_schema_flag_and_alias_conflict`、`test_current_database_dry_run_reports_no_changes_without_plan_file`、`test_dry_run_and_guarded_apply`；`test_repository_migrations.py::test_req_mig_005_rejects_tampered_plan_body_with_unchanged_plan_id`、`test_req_mig_005_rejects_rehashed_semantically_forged_current_plan`、`test_req_mig_005_plan_parser_rejects_nonexact_document_shapes` | `CODE-MIG-005` · `MigrationPlan.from_dict/read/write/validate_integrity`、`MigrationRunner.status/plan/apply` | `verified` |
| `REQ-MIG-006` | `DES-MIG-006` · 本文“指纹、事务与幂等” | receipt 不绑定可变 live fingerprint；合法写入后 status/重试仍幂等 | `TEST-DB-MIG-006` · `test_repository_migrations.py::test_atomic_idempotent_apply`、`test_stale_plan_does_not_write`、`test_req_mig_006_apply_of_current_plan_is_a_zero_write_noop`；`test_migration_recovery.py::test_req_mig_006_receipt_survives_legitimate_postmigration_writes`、`test_second_apply_reports_busy_without_writing` | `CODE-MIG-006` · `MigrationRunner.status/plan/apply`、`Repository._validate_migration_receipt_chain`、`_MigrationLock` | `verified` |
| `REQ-MIG-007` | `DES-MIG-007` · 本文“备份、恢复与保留” | 最终 descriptor 全程保有；不写/删替换 inode；流式 hash、fsync 与恢复复验 | `TEST-RECOVERY-MIG-007` · `test_migration_recovery.py::test_backup_restore_round_trip`、`test_req_mig_007_restore_never_deletes_an_existing_destination`、`test_req_mig_007_rejects_backup_directory_inside_a_repository`、`test_req_mig_007_backup_create_race_never_deletes_foreign_file`、`test_req_mig_007_backup_cleanup_preserves_replacement_inode`、`test_req_mig_007_backup_never_writes_a_replacement_inode`、`test_req_mig_007_restore_cleanup_preserves_replacement_inode`、`test_req_mig_007_backup_hashing_is_streaming` | `CODE-MIG-007` · `SqliteBackupService.create/restore`、descriptor identity helpers、`_sha256_file/_sha256_descriptor` | `verified` |
| `REQ-MIG-008` | `DES-MIG-008` · 本文“故障语义” | malformed 输入、伪造 receipt、shape 损坏、commit unknown/postcommit race 都安全失败 | `TEST-FAULT-MIG-008` · `test_cli_migrations.py::test_req_mig_008_malformed_sqlite_status_has_stable_safe_exit`、`test_req_mig_005_malformed_resolution_has_stable_safe_exit`；`test_migration_recovery.py::test_req_mig_008_fresh_database_rejects_forged_applied_receipt`、`test_commit_unknown_is_recoverable_by_status_and_idempotent_retry`、`test_req_mig_008_postcommit_mismatch_never_reports_success` | `CODE-MIG-008` · `MigrationError`、`Repository.ensure_readable`、`MigrationRunner.status/apply`、`cli.main` | `verified` |
| `REQ-MIG-009` | `DES-MIG-009` · 本文“切换与回退” | legacy 禁写但历史可读；切换后可继续 v1 导入、匹配与快照 | `TEST-E2E-MIG-009` · `test_migration_e2e.py::test_legacy_to_v1_cutover`；`test_cli_migrations.py::test_legacy_write_commands_fail_with_migration_required_without_mutation` | `CODE-MIG-009` · `Repository.ensure_writable`、`Repository.readonly_session`、CLI version gate | `verified` |
| `REQ-MIG-010` | `DES-MIG-010` · 本文“行元数据身份” | legacy preflight 与 current read 均拒绝行/payload 身份漂移 | `TEST-DB-MIG-010` · `test_contract_and_storage_invariants.py::test_legacy_preflight_rejects_row_metadata_payload_mismatches`、`test_current_repository_reads_reject_row_metadata_payload_mismatches` | `CODE-MIG-010` · `_entity_row_matches_payload`、`_outcome_row_matches_payload`、`Repository._decode_payload` | `verified` |
