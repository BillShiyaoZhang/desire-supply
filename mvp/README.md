# 愿作礼宾式 MVP

这是一套只供发起人本地使用的确定性运营工具。它不运行公开服务器，不存放联系人资料，不处理合同签署或资金，也不替代发起人的访谈、解释和协调。

## 交付内容

- `src/desire_mvp/`：校验、预算、硬过滤、排序、解释、决策快照和报告
- `config/`：带版本的词表、预算假设、匹配权重和原因代码
- `templates/`：从访谈到项目复盘的 11 份可直接复制模板
- `operations/`：启动清单、运营手册、招募话术和资料保护流程
- `samples/`：3 个虚构需求、8 个虚构创作者和 1 个虚构结果
- `tests/`：边界、确定性、隐私和报告测试
- `local-data/`：本机数据库与报告；除 `.gitkeep` 外不会进入 Git

## 五分钟跑通

需要 Python 3.9+ 和 `uv`。项目无第三方运行时依赖。

```bash
cd mvp
uv run mvp init
uv run mvp import creator samples/creators.json
uv run mvp import demand samples/demands.json
uv run mvp validate demand demand-demo-001
uv run mvp budget demand-demo-001
uv run mvp match demand-demo-001 --top 3
uv run mvp explain demand-demo-001 creator-demo-001
uv run mvp decision demand-demo-001 --selected creator-demo-001 --invited creator-demo-001 creator-demo-002 --responses samples/responses.json --reason ALGORITHM_TOP
uv run mvp outcome project-demo-001 --file samples/outcome.json
uv run mvp report pilot-demo
```

最后两个文件生成在 `local-data/reports/pilot-demo/`。以上资料全部虚构，可以安全提交或删除。

运行测试：

```bash
cd mvp
uv run python -m unittest discover -s tests -v
```

## 日常命令

```text
mvp init
mvp import creator <json-file>
mvp import demand <json-file>
mvp list creator
mvp list demand --pilot <pilot-id>
mvp validate creator <creator-id>
mvp validate demand <demand-id>
mvp budget <demand-id>
mvp match <demand-id> --top 3
mvp explain <demand-id> <creator-id> [--format markdown|json]
mvp decision <demand-id> --selected <creator-id> --invited <ids...> --responses <json-file> --reason <code>
mvp outcome <project-id> --file <json-file>
mvp report <pilot-id> [--output-dir <directory>]
```

全局参数 `--data-dir` 和 `--config-dir` 必须放在子命令前。例如：

```bash
uv run mvp --data-dir /an/encrypted/location init
```

### 预算门槛

- `RED`：命令拒绝匹配；缩小范围或提高预算后重新导入需求。
- `YELLOW`：默认拒绝；若发起人确认合理例外，使用 `--allow-yellow --reason "..."` 留痕。
- `GREEN`：可进入硬过滤与排序。

基准是首批试验假设，不是精确市场价格。来源写在 `config/budget-v1.yaml`；得到真实证据后新建 `budget-v2.yaml`，不要修改旧版本。

### 输入约定

输入使用 UTF-8 JSON。单个文件可以是一个对象或对象数组。完整字段示例见：

- `samples/demands.json`
- `samples/creators.json`
- `samples/outcome.json`
- `samples/responses.json`

身份、姓名、邮箱、电话、微信号和地址必须保存在单独的加密联系人存储中。导入器会拒绝常见身份字段。数据库只使用随机 ID；证据字段只保存不含身份的引用，不保存原文件。

### 决策留痕

每次 `match` 都写入一个不可变快照，保存当时的需求、候选资料、规则版本、过滤原因、分项和顺序。之后修改资料或配置不会改变旧快照。`explain` 从最新快照而不是当前资料生成说明。

若邀请名单与规则顺序不同，使用配置中的覆盖原因；`OTHER` 必须加 `--note`。被硬过滤的人不能通过决定命令恢复，必须先修正输入并重新匹配。

## 在真实项目开始前

必须逐项完成 [启动清单](./operations/launch-checklist.md)，特别是：确定单一适用地区、选定合规的签署/支付方式、建立加密联系人存储、完成一次无代码模拟和一次恢复演练。

字段含义与可见性见 [数据字典](./operations/data-dictionary.md)。

本工具的“完成”不等于市场验证。只有跑完 5 个进入付费阶段的真实项目、生成批次报告并作出继续/调整/停止决定，才完成首轮验证。
