# 输入契约、配置校验与原子导入

> 状态：阶段 0 已实现并验证。本文是礼宾式 MVP 输入边界的权威契约，也是目标平台正式 schema 与迁移机制的起点。

## 目标与边界

输入边界必须在资料进入持久化层或匹配计算前拒绝未知词表、错误类型和不完整配置。相同批次中的导入要么全部成功，要么完全不改变数据库，不能留下“前几条已写入、后一条失败”的部分结果。

本切片覆盖：

- taxonomy、matching、budget 和 reason-code 配置包的启动校验；
- demand、creator、outcome 的结构、类型、枚举和受控词表校验；
- CLI `import` 的整批预检与单事务写入；
- 面向后续 `schema_version` 与迁移器的兼容原则。

本切片不引入账户、网络 API、真实身份资料或通用 JSON Schema 引擎。

## 配置包契约

`manifest.json` 必须引用四类配置，声明版本必须与文件内部版本完全一致。加载成功还要求下列语义成立。

### Taxonomy

- `domains`、`problem_types`、`tasks`、`skills` 是非空、无重复的字符串数组；
- 标签使用小写 kebab-case；
- 空字符串、布尔值、数字、对象和重复标签均使配置加载失败；
- 资料中使用的领域、问题类型、任务和技能必须属于相应数组。

### Matching

- `weights` 必须且只能包含当前引擎六个分项：`interest`、`capability`、`availability`、`compensation`、`collaboration`、`evidence_trust`；
- 每个权重是有限的非负实数，布尔值不算数字，总和容差内等于 `1.0`；
- `hard_filter_order` 必须无重复，并完整列出引擎会产生的硬过滤代码；
- 配置清单不改变代码行为，也不承诺过滤器的执行顺序；该历史字段在 v2 中只作为实现—配置的集合一致性检查，缺项或未知项均拒绝启动；
- 当前 manifest 必须指向完整的 `matching-v2`。仅当显式加载原始 `matching-v1` 历史配置进行重放时，允许它缺少后来补登记的 `CREATOR_INACTIVE` 和 `CURRENCY_MISMATCH`；新配置不得使用该兼容例外。

### Budget

- 币种、默认地区、地区基线、技能系数、三类风险表、缓冲上限和健康阈值必须存在；
- 金额、倍率、风险率和阈值是有限非负实数，布尔值不算数字；
- `default` 地区基线必须存在；`yellow < green`，二者均大于零；
- 风险表必须覆盖需求允许的风险等级；资料中的币种、地区和技能等级不得依赖静默回退掩盖拼写错误。

### Reason codes

- `decision_override`、`candidate_response`、`project_failure` 是非空对象；
- 每个 code 使用大写 snake case，说明为非空字符串；
- 实现要求的 `OTHER` 及标准代码必须存在；配置允许增加代码，但删除已被历史事实引用的代码必须通过新版本和迁移审查。

依赖当前规则作判断或写入的 `init`、`import`、`validate`、`budget`、`match`、`decision` 和 `outcome` 命令，必须在接触业务存储前加载配置；配置错误以退出码 `2` 失败，不创建或修改业务记录。`list`、`explain` 和 `report` 只读取已持久化事实或规则快照，刻意不依赖“今天”的配置，否则历史结果会因当前配置损坏而变得不可读取。

## 资料契约

资料在进入业务规则前先经过两层互补契约，二者都通过才算合法：

1. **静态 v1 contract**：`mvp/schemas/*-v1.schema.json` 是公开、机器可读的结构契约；`desire_mvp.schema` 是零第三方依赖的运行时镜像，关闭对象边界，并统一执行 required、数组唯一性与最小项数、容器/标量类型、数值范围、枚举、真实日历日期和隐私安全 ID 规则。普通 validator、Repository 当前读写边界和 v0→v1 迁移目标都执行同一组不变量，不能因为入口不同而接受不同的静态资料；
2. **动态 `ConfigBundle` contract**：validator 接收完整 `ConfigBundle`，而不是忽略的可选 `rules`，继续核对 taxonomy、预算键、reason code 和跨字段业务语义。静态 schema 不复制会随配置版本变化的词表。

未知属性是 `BLOCKER / UNKNOWN_FIELD`。对外错误路径可以保留受实现控制的已知父路径和数组下标，但未知键名片段一律固定为 `<unknown-field>`，例如 `payment.plan[0].<unknown-field>`；用户提交的键名、值和身份字段都不能进入错误摘要。

字段可分为四类：

| 类别 | 示例 | 失败行为 |
| --- | --- | --- |
| 结构 | 对象、数组、字符串、布尔值、有限数字 | `BLOCKER / INVALID_TYPE` |
| 必填 | id、范围、验收、可用性、报酬边界 | `BLOCKER / MISSING_REQUIRED` |
| 枚举 | 状态、风险、数据敏感度、币种、技能等级 | `BLOCKER / UNKNOWN_ENUM` |
| 词表 | domain、problem type、task、skill tag | `BLOCKER / UNKNOWN_TAXONOMY` |

Python 中 `bool` 是 `int` 的子类，但本契约明确规定 `true/false` 不能作为金额、小时、天数、比例或熟练度通过。所有进入公式的数字还必须有限，`NaN` 和无穷值无效。

### Demand 受控字段

- `status`：阶段 0 的 v1 写值为 `draft | clarifying | verified | funded | matching | agreed | cancelled`；历史 v0 终态别名 `closed` 只允许进入显式迁移器，或由完整 legacy 指纹保护的冻结只读适配器读取；常规 v1 `import` 明确拒绝它；状态转换将在独立工作流切片中收口，当前导入只校验值；
- `problem.domain` 与 `matching.domains`：taxonomy domains；
- `matching.problem_types`：taxonomy problem types；
- `matching.tasks`：taxonomy tasks；
- `skills.must_have`、`skills.nice_to_have`：taxonomy skills；
- `skills.level`：budget skill multipliers 的键；
- `risk.uncertainty | urgency | external_dependencies`：对应 budget 风险表的键；
- `risk.data_sensitivity`：`public | low | medium | high | restricted`；
- `budget.currency`：当前预算配置币种；
- `location.region`：地区基线的显式键；允许的创作者地区是地域标识，不由预算表限制。

以下证据字段刻意保持条件语义，不是静态 schema 的无条件 required：

- `funding_evidence_ref` 缺失或为显式空字符串 `""` 时产生 `QUESTION / FUNDING_EVIDENCE_REFERENCE`，不单独阻止保存或匹配就绪；JSON `null` 不是“未填写”，而是 `BLOCKER / INVALID_EXTERNAL_REFERENCE`；一旦提供非空值，必须通过下节受控外部引用语法；
- `risk.data_handling_plan` 在 `public | low | medium` 下可省略；`high | restricted` 下缺失时是 `BLOCKER / MISSING_DATA_PLAN`；
- `ai.data_model_policy` 在低敏场景可省略；只有允许 AI 且数据为 `high | restricted` 时，缺失才是 `BLOCKER / MISSING_AI_DATA_POLICY`。

### 受控外部引用

`funding_evidence_ref`、创作者技能的 `evidence_ref`、迁移 resolution 的 `evidence_ref` 以及安全事件的 `event_ref` 只保存受控系统中的匿名引用，不保存联系人、证据正文或可直接访问的网络地址。统一语法为：可选的字面前缀 `external://`，随后是 2–128 位、以 ASCII 字母开头且只含 ASCII 字母、数字、`_`、`-` 的 slug；slug 不得包含 7 位以上连续数字。等价基础形状是 `[A-Za-z][A-Za-z0-9_-]{1,127}`，再叠加连续数字限制。

因此 `evidence-demo-001` 与 `external://migration-review-001` 合法；含 `@`、`?query`、`#fragment`、额外 `/`、普通 `http://`/`https://` URL、纯数字或 7 位连续数字的值均拒绝。引用的真实性和访问授权由外部受控系统负责，本地 MVP 只验证安全语法，不能把“格式合法”解释为证据已核实。

### Creator 受控字段

- `status`：v1 写值为 `active | paused | inactive`；历史 v0 终态别名 `withdrawn` 只允许进入显式迁移器，或由完整 legacy 指纹保护的冻结只读适配器读取；常规 v1 `import` 明确拒绝它，迁移器唯一映射为 `inactive`；
- interests 中的 problem types、domains、tasks：对应 taxonomy；
- `skills[].tag`：taxonomy skills；
- `proficiency`、`evidence_trust`：`0..4` 的有限数字；
- `boundaries.allowed_data_sensitivity`：与 demand 相同的数据等级；禁止领域/任务可表达平台词表之外的安全边界，不能因 taxonomy 未收录而拒绝；
- `conflicts[]`：匿名组织关联 ID，逐项应用与实体 ID 相同的隐私安全语法；
- `compensation.currency`：当前预算配置币种；
- `collaboration.languages`、`work_mode` 等开放协作标识在本版本只做类型与非空校验，待多语言/协作策略版本化后再收紧。

`creator.ai.prohibited_cases` 同样不是静态 required；缺失或为空产生 `QUESTION / AI_PROHIBITED_CASES`，用于提示运营者补充偏好，不把创作者排除出匹配。一旦提供，它必须是无重复的非空字符串数组。

所有实体 ID、关联 ID 和里程碑 ID 只能使用 2–128 位 ASCII 字母、数字、`_`、`-`，并以字母或数字开头；还必须至少含一个字母，且不得包含 7 位以上的连续数字。它们是无身份含义的公开引用，邮箱、电话、路径、对象或自由文本均不能作为 ID。语法检查不能证明一个字符串没有身份含义，因此运营侧仍须生成随机 ID，任何失败批次的错误摘要都只给数组下标和固定 `<redacted>`，永不回显输入 ID。日期使用真实存在的 `YYYY-MM-DD` 日历日期；付款计划百分比总和必须为 100；金额、容量和计数不得为负，计数必须是整数。

### Outcome 受控字段

`Outcome` 使用 reason-code 配置校验 `failure_primary` 和 `failure_secondary`；完成状态不得填写相互矛盾的失败事实，失败/退出必须填写有效首要原因。创作者偏好和再次合作数组必须与 `creator_ids` 等长，里程碑字段、运营工时分类、日期先后和整数计数都在写入前验证。

`safety_events` 是可为空的数组，但不再接受开放对象。每一项必须且只能包含：

```json
{
  "event_ref": "external://safety-event-demo",
  "severity": "high"
}
```

- `event_ref` 必须通过上节受控外部引用语法；
- `severity` 只能是 `low | medium | high | critical`；
- 两个字段都 required，事件对象 `additionalProperties: false`，缺项、未知字段或非对象元素都是 `BLOCKER`。

这是供匹配后复盘、统计和安全升级判断使用的最小事件投影。事件叙述、当事人身份、处置记录和证据正文继续留在独立受控安全系统，本地资料不得复制这些内容。

### 固定跨字段不变量

不会随 taxonomy、预算版本或 reason-code 配置变化的矛盾规则属于静态 v1 contract，而不是只在某个 CLI 用例中执行的“就绪检查”。因此 runtime validator、Repository 当前读写和迁移目标必须共同拒绝：

- demand 的付款计划百分比合计不等于 100、`due_date < start_date`、`budget.minimum > budget.maximum`；
- creator 的 `skills[].tag` 重复，即使重复项使用不同证据引用；
- completed outcome 的 `real_payment` 不为 `true`，或同时带首要/次要失败原因；
- exited/failed outcome 缺少 `failure_primary`；
- `creator_preference_confirmed` 或 `willing_to_use_again.creators` 与 `creator_ids` 长度不同；
- outcome 的 planned/actual finish 早于对应 start。

动态 validator 仍负责 taxonomy、配置枚举、reason code 有效性和匹配就绪问题；但不能用未加载 ConfigBundle 作为绕过上述固定不变量的理由。

### SQLite 行元数据与 payload 身份

SQLite 的检索/索引列不是可以与 JSON 各自漂移的缓存。当前库写入时由 payload 派生行元数据，读取时再逐项核对：

- `entities` 的 `kind`、`entity_id` 必须对应资料类型与 `payload.id`；demand 的行 `pilot_id` 必须等于 `payload.pilot_id`，creator 的行 `pilot_id` 必须为 `NULL`；
- `outcomes` 的 `project_id`、`pilot_id`、`demand_id` 与规范化 `creator_ids_json` 必须分别等于 payload 同名字段。

current 读取发现不一致时以 `INVALID_PAYLOAD_SCHEMA` fail closed，不返回其中任一版本。legacy dry-run 在转换前执行同一身份核对；不一致产生脱敏 blocker `LEGACY_ROW_METADATA_MISMATCH`，整库不得 apply。迁移器不能猜测“行列”或“JSON”哪一份才是真值，也不能静默修复。

## 原子导入协议

`mvp import <kind> <file>` 按以下固定顺序执行：

1. 加载并完整校验配置包；
2. 读取 UTF-8 JSON，根节点只能是对象或对象数组；
3. 对整批每条记录执行身份字段扫描、静态 v1 contract（含固定跨字段不变量）、动态 ConfigBundle 语义和批内 ID 唯一性检查；决策权和资金承诺只决定匹配就绪，不阻止保存一份结构合法的草稿；
4. 任一记录失败时，输出只包含数组下标、固定 ID 占位符和受实现控制的字段/错误代码；身份字段的路径固定脱敏，未知字段的未知键名固定为 `<unknown-field>`，用户键名不能进入错误，数据库保持命令开始前状态；
5. 全部通过后，在一个数据库事务中 upsert 整批记录；
6. 成功输出按输入顺序列出 ID 和数量。

即使目标 ID 已存在，也不能在批次失败时更新旧值。空数组不是有效导入；同一文件出现重复 ID 视为调用错误，而不是“最后一条覆盖前一条”。

Repository 提供单一 `put_entities(kind, records)` 事务边界；`put_entity` 可保留为单条兼容封装，但 CLI 不得循环调用它制造多个事务。

## 版本与迁移方向

当前 demand、creator、outcome 的常规输入与发布样例已要求根级整数 `schema_version: 1`。[Schema 与存储迁移](/architecture/schema-and-storage-migrations.md)收口了完整迁移设计；本切片已经完成其中的 v1 资料边界：

1. `mvp/schemas/` 发布 demand、creator、outcome 三份机器可读 v1 schema；
2. 三类 validator 与 Repository 当前读写边界不猜测、不强制转换版本；
3. 缺失、旧版、布尔值、字符串或未来版本统一产生 `UNSUPPORTED_SCHEMA_VERSION`；
4. v0 只存在于冻结的历史夹具，并只允许进入显式迁移器或历史快照解码器；
5. SQLite registry、只读 dry-run、单事务 apply、备份恢复、旧推荐快照不变与 commit-unknown 恢复均已由迁移切片实现并测试。

静态 v1 contract 与 `ConfigBundle` 驱动的动态 taxonomy、reason code 和跨字段规则必须同时通过。静态 contract 在 runtime validator、Repository 当前读写与迁移目标上保持 required、unique/min-items、type/range/enum、date、ID 和受控引用行为一致；任何常规读取或写入都不得静默补版本、放行损坏 payload 或改写历史资料。

## 验收条件

以下场景必须先成为失败测试：

- taxonomy 中的未知 domain、problem type、task 或 skill 产生 `UNKNOWN_TAXONOMY`；
- 未知风险等级、技能等级、币种、数据等级或状态产生 `UNKNOWN_ENUM`；
- 对象/数组类型颠倒、布尔值冒充数字、`NaN`/无穷值产生 `INVALID_TYPE`；
- 受控外部引用拒绝联系人形态、普通 URL、查询串和 7 位连续数字；`safety_events` 只接受完整的 `{event_ref, severity}` 最小投影；
- 固定跨字段矛盾在 validator、Repository 与迁移目标上得到相同拒绝；SQLite 行元数据与 payload 身份不一致时 current 读取和 legacy 迁移均 fail closed；
- 权重缺项、多项、非数值、总和不为 1，以及硬过滤清单缺项会使 `load_config` 失败；
- 批量文件第二条含身份字段、无效词表或重复 ID 时，第一条也不会写入；
- 合法样例仍能导入、校验、预算、匹配、解释和报告；
- 错误输出不包含创作者私密金额、联系方式形态的无效 ID 或整条敏感输入。

## 追踪

| 需求 ID | 设计责任 | 测试证据 | 实现入口 | 状态 |
| --- | --- | --- | --- | --- |
| `MVP-IN-001` | 四类配置的版本与完整语义 | `test_config.py` 配置变异矩阵 | `desire_mvp.config.load_config` | 已实现 |
| `MVP-IN-002` | 静态 v1 contract 与动态 ConfigBundle 的双层资料约束 | `test_validation.py::test_runtime_preserves_conditional_evidence_semantics` 及契约矩阵；`test_schema_versions.py::test_runtime_rejects_unknown_fields_at_closed_schema_boundaries`、`test_validation_errors_never_reflect_unknown_keys_or_skill_tags`、`test_current_repository_reads_fail_closed_on_corrupt_payload`、`test_controlled_references_and_closed_safety_event_projection`、`test_optional_funding_reference_empty_missing_and_null_semantics`；`test_contract_and_storage_invariants.py::test_demand_contract_rejects_fixed_cross_field_contradictions`、`test_creator_contract_rejects_duplicate_skill_tags`、`test_outcome_contract_rejects_fixed_state_and_cardinality_contradictions` | `desire_mvp.schema`、`validate_demand/creator/outcome`、`Repository` | 已实现 |
| `MVP-IN-008` | SQLite 行元数据与 payload 身份绑定 | `test_contract_and_storage_invariants.py::test_legacy_preflight_rejects_row_metadata_payload_mismatches`、`test_current_repository_reads_reject_row_metadata_payload_mismatches` | `Repository._decode_payload`、`MigrationRunner.plan`、row identity helpers | 已实现 |
| `MVP-IN-003` | 整批预检、空批次与重复 ID | `test_cli.py` 导入契约 | `cmd_import` | 已实现 |
| `MVP-IN-004` | 单事务 upsert，失败时不覆盖旧值 | `test_repository_and_reports.py` 回滚测试；`test_cli.py` 失败批次测试 | `Repository.put_entities` | 已实现 |
| `MVP-IN-005` | 对外错误只包含安全索引、固定 ID 占位符与错误代码 | `test_cli.py` 私密金额、对象 ID、手机号/邮箱 ID、合法形态 ID 回归 | `cli.main`、`is_public_identifier`、privacy helpers | 已实现 |
| `MVP-IN-006` | PR/main 的代码与文档自动门禁 | GitHub Actions `ci.yml`；本地全量命令 | `.github/workflows/ci.yml` | 已实现 |
| `MVP-IN-007` | [显式 schema 版本、SQLite migration registry 与 v0→v1 迁移器](/architecture/schema-and-storage-migrations.md) | `test_schema_versions.py`、`test_migrations.py`、`test_repository_migrations.py`、`test_cli_migrations.py`、`test_migration_recovery.py`、`test_migration_e2e.py` | `desire_mvp.schema`、`desire_mvp.migrations`、`desire_mvp.migration_support`、`Repository`、`cli.cmd_migrate` | 已实现并验证 |
