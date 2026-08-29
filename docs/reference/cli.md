# CLI 参考

## 调用方式

在 `mvp/` 目录中使用：

```bash
uv run mvp [全局参数] <子命令> [参数]
```

也可以安装包后直接运行 `mvp`，或使用 `python -m desire_mvp`。

## 全局参数

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `--data-dir` | `mvp/local-data` | 匿名 SQLite 与报告根目录 |
| `--config-dir` | `mvp/config` | manifest 和版本化规则目录 |

全局参数必须写在子命令前：

```bash
uv run mvp --data-dir /encrypted/desire-data init
```

## 子命令

### `init`

初始化 SQLite schema，加载并核对规则配置。

```bash
uv run mvp init
```

输出数据库路径、复合规则版本和 `ready` 状态。

`init` 只会建立空库或核对当前版本库，不会顺手修改 legacy 库。检测到待迁移库时以 `MIGRATION_REQUIRED` 和退出码 2 停止。

### `migrate`

先以只读方式查询状态：

```bash
uv run mvp migrate status
uv run mvp migrate status --plan-id <plan-id>
```

`status` 不调用 `init`，也不创建 data directory、数据库或 SQLite 旁路文件。状态分类、current 受管 table 定义与全量 index/trigger 精确集合、registry/receipt chain 及可选 plan receipt 查询都在同一只读事务快照内完成；未知 trigger 同样失败。`applied` 表示不可变切换 receipt 有效，不要求后来可合法变化的业务 live fingerprint 仍等于切换指纹。输出只包含状态、固定代码、源/目标版本和可选 plan ID。

迁移必须先生成并人工审核计划，再显式 apply：

```bash
uv run mvp migrate --payload-schema 1 --dry-run \
  --plan-out <secure-new-plan.json> \
  [--resolutions <secure-resolutions.json>]

uv run mvp migrate --payload-schema 1 --apply \
  --plan <secure-plan.json> \
  --backup-dir <existing-encrypted-backup-dir> \
  [--resolutions <secure-resolutions.json>]
```

`--payload-schema 1` 是正式参数；`--to 1` 仅作为旧测试和旧草案脚本的兼容别名，两者不能同时使用。`--dry-run` 与 `--apply` 互斥。

dry-run 在一个只读事务中完成 frozen legacy/current DDL 识别、源指纹、转换目标和推荐摘要；legacy plan 还在同一快照核对行元数据↔payload 身份。对 legacy，唯一允许的写入是调用者指定且原先不存在的 plan 文件；plan 以 `0600` 权限创建，只保存版本、摘要、计数、固定 blocker code 和 plan ID，不保存业务 payload 或 resolution evidence。即使存在 blocker，命令仍先写出这份脱敏计划，再返回退出码 2。若数据库已经是完整 v3/v1，命令返回 `status: no_changes`，数据库保持零写入，并且不会创建 `--plan-out` 指定的文件。

plan 是关闭强类型文档：根字段、migration、counts 和 blockers 都不得缺项、增项或强制转换；descriptor 列表、版本轴、非负计数、排序唯一 blocker 和摘要格式必须精确。plan ID 绑定除自身外的全部字段，读写时重算；apply 还从当前事实重建语义 plan，所以篡改后自行重算 ID 也不能绕过。

apply 只接受无 blocker 且与当前源库、migration checksum 和 resolution 文件完全一致的 plan。缺少 `--plan` 或 `--backup-dir` 会在任何迁移或备份前失败。备份目录必须已存在、位于 data directory 之外且不处于 Git worktree 内；SQLite backup 先在私有 staging 文件完成，随后经始终保有的最终 exclusive descriptor 流式复制并 `fsync`，不会按最终路径重开写入，完成 backup 与 manifest 后还会 `fsync` 目录。备份/manifest/restore 失败清理只删除仍由本进程 descriptor 拥有的 inode，替换文件保持不动。成功输出只包含结果状态、plan ID 和是否创建备份，不回显 payload、证据或备份文件路径。重复 apply 同一已完成 plan 返回 `already_applied`，不再创建备份；合法迁移后业务写入不会让 receipt 失效。

resolution 文件结构为：

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

resolution 根对象只能包含整数 `schema_version: 1` 与 `demand_status_resolutions` 数组；每项必须且只能包含五个字符串字段。`closed` demand 必须逐条裁决为 `agreed` 或 `cancelled`，目标与 reason code 组合受控，`evidence_ref` 使用安全外部引用语法。缺失、重复、未使用、未知字段、错误标量/容器或相互矛盾的裁决都会以 `INVALID_DEMAND_STATUS_RESOLUTION`/blocker 安全失败；不会输出原值、`TypeError` 或 traceback。文件只放外部证据引用，不能放证据正文或联系人资料。

### `import`

```bash
uv run mvp import creator <json-file>
uv run mvp import demand <json-file>
```

文件可以是一个 JSON 对象或对象数组。命令先对整批资料检查身份字段、必填结构、类型、受控词表、枚举和重复 ID；任一条失败时整批零写入。失败摘要只给数组下标、固定 ID 占位符和错误代码，不回显输入 ID 或整条记录。全部通过后在一个事务中按 `(kind, id)` 更新当前资料。导入通过仍不代表资料可进入匹配：决策权和资金承诺等运行门槛由 `validate` 再次检查。

### `list`

```bash
uv run mvp list creator
uv run mvp list demand --pilot <pilot-id>
```

只输出 ID、状态和 pilot ID，不输出完整资料。

迁移窗口内，`list`、`explain` 和 `report` 是仅有的 legacy 兼容业务命令；它们先验证冻结的 legacy 结构，再通过 SQLite read-only 连接读取，绝不调用 `init` 或写回数据库。其余业务命令在迁移完成前均以 `MIGRATION_REQUIRED` 阻断。

### `validate`

```bash
uv run mvp validate creator <creator-id>
uv run mvp validate demand <demand-id>
```

输出 `entity_type`、`entity_id`、`status`、`ready` 和问题数组。存在 `BLOCKER` 时退出码为 1；`WARNING` 与 `QUESTION` 不阻断。

### `budget`

```bash
uv run mvp budget <demand-id>
```

需求校验通过后才计算。输出劳动基线、直接成本、风险缓冲、建议最低预算、预算上限、比率、健康度、配置版本和全部假设。

### `match`

```bash
uv run mvp match <demand-id> [--top 1..5]
uv run mvp match <demand-id> --allow-yellow --reason "书面理由"
```

前置条件：需求无 `BLOCKER`；预算不是 `RED`；`YELLOW` 已显式允许并说明。命令验证创作者、硬过滤、排序、写入推荐快照，再输出顶部候选与对外说明。默认 `--top 3`。

### `explain`

```bash
uv run mvp explain <demand-id> <creator-id>
uv run mvp explain <demand-id> <creator-id> --format json
```

从该需求最新推荐快照解释合格候选。默认输出 Markdown。若候选被硬过滤、未在快照中或输出触发泄漏保护，命令失败。

### `decision`

```bash
uv run mvp decision <demand-id> \
  --selected <creator-id> \
  --invited <creator-id> [<creator-id> ...] \
  --responses <responses.json> \
  --reason <reason-code> \
  [--note "补充事实"]
```

未成交时省略 `--selected`。未显式传 `--invited` 时，有 selected 则默认只邀请 selected。被邀请者和 selected 必须在合格排序中；`OTHER` 原因或反馈必须补 note。

### `outcome`

```bash
uv run mvp outcome <project-id> --file <outcome.json>
```

命令行 ID 必须与文件内 `project_id` 一致。结果通过校验后按项目 ID 写入/更新。

### `report`

```bash
uv run mvp report <pilot-id>
uv run mvp report <pilot-id> --output-dir <directory>
```

默认输出到 `<data-dir>/reports/<pilot-id>/report.md` 和 `metrics.csv`。报告使用每个需求的最新决定/推荐与每个项目的当前结果。

## 退出码和输出

| 退出码 | 含义 |
| ---: | --- |
| `0` | 成功 |
| `1` | `validate` 发现 `BLOCKER` |
| `2` | 预期的 CLI、配置、资料、决定或查找错误 |
| `3` | 迁移 commit 结果无法判定，代码为 `MIGRATION_RECOVERY_REQUIRED`；需人工核对 `migrate status --plan-id`，禁止自动重试 |
| 其他 | 未捕获的程序或运行环境错误 |

除 `explain --format markdown` 外，命令成功输出优先为格式化 JSON。自动化调用必须同时检查退出码，不要只匹配中文错误文字。

## 输入安全

输入应为 UTF-8。真实文件不得提交到仓库。姓名、邮箱、电话、微信、身份证、地址、合同、付款凭据和原始证据保存在独立受控系统；样例中的 `external://...` 与 `evidence-demo-...` 只是虚构引用格式。
