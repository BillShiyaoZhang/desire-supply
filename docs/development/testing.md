# 测试与质量

## 当前测试策略

测试使用 Python 标准库 `unittest`，以虚构 JSON 样例作为契约夹具。重点不是追求行覆盖率，而是保护会影响参与机会、报酬和隐私的不变量。

```bash
cd mvp
uv run python -m unittest discover -s tests -v
```

文档单独验证：

```bash
python3 scripts/verify_docs.py
```

## 已覆盖行为

| 测试文件 | 保护的行为 |
| --- | --- |
| `test_config.py` | manifest 固定四个规则版本；权重总和为 1 |
| `test_validation.py` | 样例可匹配；资金、验收、敏感数据计划、技能证据和失败原因门槛 |
| `test_budget.py` | 建议预算可追溯；0.8/1.0 边界；风险缓冲封顶 |
| `test_matching.py` | 输入顺序不影响排名；必需技能、私密底线和边界是硬过滤 |
| `test_privacy.py` | 匹配说明不泄露私密底线；嵌套身份字段被拒绝 |
| `test_decisions.py` | 选择和反馈有效；被过滤者不能恢复；`OTHER` 需要说明 |
| `test_repository_and_reports.py` | 推荐快照不受资料更新影响；结果进入报告；Markdown/CSV 可生成 |

## 风险驱动的测试金字塔

### 纯规则单元测试

对 validation、budget、matching、privacy 和 decisions 使用小字典构造边界。每条硬过滤至少需要“命中”和“接近但不命中”两个测试，尤其关注日期等号、金额等号、空列表、未知枚举和类型错误。

### 仓库集成测试

使用临时目录创建真实 SQLite，验证 schema 初始化、upsert/append 语义、外键、旧库迁移、快照、报告与删除工具。测试不得写入默认 `mvp/local-data`。

### CLI 契约测试

目前主要通过函数测试间接覆盖。下一步应使用子进程验证：退出码、stdout JSON、stderr、全局参数顺序、文件不存在、非法 JSON、YELLOW 例外和所有子命令帮助。CLI 是运营脚本的接口，文字变化也可能破坏使用。

### 端到端样例

固定跑通 `init -> import -> validate -> budget -> match -> explain -> decision -> outcome -> report`。断言推荐 ID、候选顺序、过滤原因、报告关键指标和私密值均符合预期。

## 建议补充的测试

优先级从高到低：

1. 所有硬过滤代码的参数化边界测试；
2. 数据库升级和删除覆盖推荐快照的测试；
3. CLI 子进程退出码与 JSON 契约；
4. 自由文本中身份信息的人工/自动预检；
5. 新旧规则版本对同一历史批次的差分测试；
6. 报告在无推荐、无决定、退出/失败和重复结果下的行为；
7. 备份恢复后的完整端到端冒烟测试。

## 确定性与黄金数据

匹配引擎不得依赖当前时间、随机数、输入迭代顺序、网络或全局状态。日期必须来自输入。黄金样例可以锁定排序与解释结构，但不应大段锁定中文字符串而让合理文案修改困难；更重要的是锁定原因代码、分项、总分、规则版本和隐私不变量。

如果未来引入语义模型，模型只能生成建议特征或文本，必须：固定模型/提示版本、保存输入输出、设置超时和失败降级、用确定性硬过滤包围，并禁止其独立改变资格与付款。

## 文档质量门槛

`verify_docs.py` 检查：

- 每个内容页以一级标题开始；
- 每个内容页都出现在侧边栏；
- 站内链接不能失效或逃出 Pages artifact；
- 代码围栏成对；
- 不出现不可移植的本机文件 URL；
- Docsify 入口与 Pages workflow 包含关键配置。

它不验证外部链接、中文事实、架构图语义或代码/文档一致性，这些仍需评审。

## 持续集成建议

当前 GitHub Actions 在文档部署前只运行文档校验。开始多人开发后，应增加独立 CI，在 pull request 和 `main` push 上运行：

```bash
cd mvp && uv run python -m unittest discover -s tests -v
python3 scripts/verify_docs.py
```

依赖下载需要 lockfile，Actions 使用固定提交 SHA；失败时不部署。涉及规则变化的 PR 应上传新旧样例差分作为构建 artifact，供业务与工程共同审查。
