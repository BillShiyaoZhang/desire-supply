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

### `import`

```bash
uv run mvp import creator <json-file>
uv run mvp import demand <json-file>
```

文件可以是一个 JSON 对象或对象数组。导入前递归拒绝常见身份字段；同 kind 和 ID 会更新当前资料。导入不代表资料已经通过 `validate`。

### `list`

```bash
uv run mvp list creator
uv run mvp list demand --pilot <pilot-id>
```

只输出 ID、状态和 pilot ID，不输出完整资料。

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
| 其他 | 未捕获的程序或运行环境错误 |

除 `explain --format markdown` 外，命令成功输出优先为格式化 JSON。自动化调用必须同时检查退出码，不要只匹配中文错误文字。

## 输入安全

输入应为 UTF-8。真实文件不得提交到仓库。姓名、邮箱、电话、微信、身份证、地址、合同、付款凭据和原始证据保存在独立受控系统；样例中的 `external://...` 与 `evidence-demo-...` 只是虚构引用格式。
