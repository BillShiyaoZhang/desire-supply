# 规则配置参考

## 配置包

`mvp/config/manifest.json` 是入口，固定四类文件：

| 类型 | 当前文件 | 决定什么 |
| --- | --- | --- |
| `taxonomy` | `taxonomy-v1.yaml` | 领域、问题类型、任务、技能标签 |
| `matching` | `matching-v2.yaml`（保留 `matching-v1.yaml`） | 六项权重与硬过滤清单 |
| `budget` | `budget-v1.yaml` | 地区基线、技能系数、风险和健康阈值 |
| `reason_codes` | `reason-codes-v1.yaml` | 决定覆盖、候选反馈和项目失败原因 |

`.yaml` 当前使用严格 JSON 语法，以便标准库读取。不要加入 YAML 注释、锚点或非 JSON 标量，除非同时引入并评审 YAML 解析依赖。

## Taxonomy

taxonomy 为访谈和匹配提供受控词表。标签使用稳定的英文 kebab-case，用户界面可以另做中文显示。批次中只能使用已冻结标签；遇到无法表达的情况先记录原始事实和 `BAD_TAXONOMY`，批次后再决定新增、合并或映射。

新增标签需要：定义、正例、反例、旧标签映射、至少一个样例和匹配回归测试。删除标签不能让历史快照无法解释。

## Matching

当前 `matching-v2` 权重与 v1 相同：

```json
{
  "interest": 0.30,
  "capability": 0.25,
  "availability": 0.15,
  "compensation": 0.15,
  "collaboration": 0.10,
  "evidence_trust": 0.05
}
```

权重总和必须为 1。`hard_filter_order` 是历史命名的策略清单与实现集合一致性契约；加载器要求 v2 与引擎可能产生的全部硬过滤代码完全一致，但不根据数组顺序驱动过滤执行。v2 只补齐 v1 遗漏的 `CREATOR_INACTIVE` 与 `CURRENCY_MISMATCH` 清单，不改变计算或资格行为。加载原始 `matching-v1` 供历史重放时保留一个精确兼容例外；新配置或 v1 的任何变体都不能借此绕过完整性检查。修改清单本身不会新增过滤，规则变化仍必须同步代码、测试和新配置版本。

## Budget

### 地区基线

`regional_daily_baselines` 按需求 `location.region` 选择。受支持的 CLI 输入边界会拒绝未知地区；预算纯函数中保留的 `default` 只为历史快照或直接库调用提供防御性计算，不能把拼写错误变成合法新输入。它代表首轮的体面劳动研究假设，不是报价上限、最低工资结论或精确市场价。

### 技能系数

需求 `skills.level` 映射 `basic/standard/advanced/expert`。受支持的 CLI 输入边界拒绝未知值；预算纯函数中的 1.0 回退同样只服务历史快照或直接库调用，不是输入契约。

### 风险

`uncertainty`、`urgency` 和 `external_dependencies` 各自映射风险率后相加，并受 `risk_buffer_cap` 限制。当前上限为 0.50。

### 健康阈值

`yellow = 0.80`、`green = 1.00`。低于 yellow 为 RED；达到 yellow 未达到 green 为 YELLOW；达到 green 为 GREEN。

`provenance` 必须写明证据状态、复查时间和变更指令。获得真实报价后保存匿名聚合证据，不能把个人私密底线写进公开配置。

## Reason codes

### 决定原因

原因应描述为什么实际邀请/选择与建议关系不同，而不是评价一个人的人格。`OTHER` 只在现有词表确实无法表达时使用，并要求简短事实 note。

### 候选反馈

当前包括接受、意愿、容量、报酬、范围、边界和其他。拒绝原因是学习信号，不形成创作者负面声誉，也不向另一方转述私密原话。

### 项目失败

失败原因覆盖资金、无匹配、范围、依赖、容量、付款、质量、沟通、安全和其他。完成项目可为空；退出/失败必须有首要原因。

## 新版本流程

不要编辑已用于真实推荐的 v1 文件。创建 v2：

1. 新文件内部 `version` 与文件名一致；
2. 更新 `effective_date` 和来源/说明；
3. 更新 manifest 的 `files` 与 `versions`；
4. 添加或修改行为测试；
5. 用旧批次进行离线差分并解释变化；
6. 在新批次开始前批准生效；
7. 保留全部旧文件。

加载器会拒绝 manifest 声明版本与文件内部版本不一致。每次推荐记录四个版本拼接成的 `rule_version`。
