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

当前阶段 0 基线中，MVP 全量 `unittest` 回归为 `134/134` 通过；功能文档仍以具体测试文件与测试名作为长期追踪证据。

目标平台 IAM 切片使用独立测试根；`platform/pyproject.toml` 的 `test` extra 精确锁定机器契约所需的 `PyYAML==6.0.3` 与真实 PostgreSQL 18 集成所需的 `psycopg[binary]==3.2.13`：

```bash
cd platform
python3 -m pip install --disable-pip-version-check '.[test]'
PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
```

2026-08-08 在policy/consent PostgreSQL切片进入GREEN前，不含刻意RED的稳定平台基线为 `362/362`：application `100/100`（Accept `49`、Issue `15`、Publish `18`、Outbox delivery `18`），OIDC/AuthTransaction/BFF Session authentication `22/22`，authority lifecycle Memory application `38/38`，HTTP/ASGI presentation `25/25`，IAM domain `11/11`、authorization `10/10`、既有OpenAPI/event contract `22/22`、IAM read model/application+contract `11/11`、policy/consent Memory application+contract `15/15`、PostgreSQL storage `108/108`。这是历史可比基线，不把后来并发落盘的新切片计入旧总数；OIDC、lifecycle、HTTP、read与Memory command证据仍只证明各自已列边界，稳定基线不证明所有真实业务UoW、生产composition/server或E2E。

`AcceptCurrentPolicies`/`GrantConsent`先得到有效语义RED：`Ran 11 tests`、`86 failures`、`0 errors`；该历史证据保留。随后保持exact requirement/current、User If-Match、Session evidence、acceptance/grant reuse、receipt/fault/privacy业务矩阵实现Memory GREEN，现为application `11/11 OK`、新增机器contract `4/4 OK`，并已纳入上述历史稳定基线。真实SELF PostgreSQL adapter也已按下一段完成GREEN；HTTP presenter/composition与E2E仍planned。完整证据见 [IAM 当前政策接受与 Consent 授予命令](/architecture/iam-policy-consent-commands.md)。

真实SELF PostgreSQL repository/UoW随后进入独立TDD阶段：动态catalog head v13的临时PostgreSQL 18测试先得到`17 methods / 33 failures / 0 errors / 0 skips`的有效历史RED。现已在forward-only v14实现GREEN，并增加一项persisted receipt metadata drift不重算护栏：目标`18/18 OK`；明确排除另一切片拥有的Creator Profile PostgreSQL刻意RED后，稳定storage为`126/126 OK`。同轮受影响非storage回归为policy/consent Memory `15/15`、Accept Memory `49/49`、当时全contract目录`59/59`。Creator Profile模块自己的34个default-deny semantic failures/0 errors单列保留，不能把全storage discovery写成GREEN；详见[PostgreSQL SELF UoW设计与证据](/architecture/iam-policy-consent-postgresql.md)。

Demand PostgreSQL切片也使用独立TDD根。首轮在真实PostgreSQL 18动态应用IAM catalog head v15，并建立合法Organization/DEMAND_OWNER权威图；production seam import成功且默认在checkout前拒绝。初始为`17 methods / 47 semantic failures / 0 errors / 0 skips`；随后MATCH_INPUT安全审计在相同17个方法内补齐完整深度不可变投影、canonical/hash与逐项hard-filter派生、同事务PG clock、partial/corrupt和repr隐私oracle，最终head 15（IAM SQL `50df44d9…373a`、manifest/review pin `ebbdeef2…9b4f`）实跑为`17 methods / 100 semantic failures / 0 errors / 0 skips`。该历史RED保留。随后基于唯一IAM head16，以独立Demand `0001`（SQL `c352e19a…d59f`、manifest/review pin `568db460…daf0`）实现10个writer、authority/FORCE RLS/PUBLIC ACL、receipt/source inbox、hold/rule race、并发、rollback、COMMIT unknown、pool reset、MATCH_INPUT与secret边界；相同17方法/100项oracle现为`17/17 OK`。排除仅剩的Taxonomy PostgreSQL intentional RED后，完整稳定storage为`177/177 OK`；Demand既有contract/domain/application `34/34 OK`、contracts目录`70/70 OK`。真实pool/composition、HTTP server、worker部署与跨Context E2E仍未由此证明；详见[Demand PostgreSQL设计与证据](/architecture/demand-postgresql.md)。

Demand所需IAM authority随后先进入独立direct-SQL TDD：动态head15上`15 methods / 15 semantic failures / 0 errors / 0 skips`，失败均为owner/reviewer关闭capability不存在。forward-only 0016 capability首次转绿后，第16个方法又分别捕获runner不能读取IAM compatibility、能读后仍不能解析`iam_api`签名的两个窄ACL RED，均为`1 failure / 0 errors / 0 skips`；最终只增加schema usage/compatibility单表读取且明确无capability EXECUTE/`iam.*` SELECT，同套件16/16 GREEN。覆盖固定签名/返回/ACL/search_path、锁序、operation+target marker、cross-scope/GUC、ACTIVE/deadline/grant与current policy acceptance，且独立reviewer User/Session不以organization membership授权。最终0016 SQL为`5bf115a9…68ba8`、IAM manifest/review pin为`8b114475…2268`；当前IAM head16上排除Demand/Taxonomy业务刻意RED的稳定storage为160/160。这只证明IAM依赖就绪，不把Demand业务schema/UoW提前计为GREEN。

Taxonomy机器契约随后独立采用contract-first TDD：在七份机器artifact不存在时，`11`个测试得到`19 failures / 0 errors`的明确结构RED；加入OpenAPI、事件与五份domain schema后同一套件`11/11 OK`。连同IAM、Profile、Demand与Matching，当前contract discovery为`70/70 OK`。这只证明关闭机器边界；Taxonomy domain/application/数据库行为仍按[Taxonomy、受控代码与规则目录](/architecture/taxonomy-and-rule-catalog.md)单独取RED，不能纳入历史`362/362`行为基线。

Matching首轮在机器契约`11/11`基础上先取得domain `13 methods / 12 semantic failures / 0 errors / 0 skips`与application `19 methods / 18 semantic failures / 0 errors / 0 skips`，实现后分别`13/13`与`19/19` GREEN。安全复审再新增receipt/replay/audit门禁，先为`7 failures / 0 errors / 0 skips`，随后`7/7` GREEN；Matching行为目标合计`39/39`。另以一次精确contract RED把独有`"N"` ETag统一为平台`"vN"`。证据只覆盖Memory fixed UoW，不代替Matching PostgreSQL/RLS、HTTP、worker部署或CompleteSelection跨Context事务。

## 已覆盖行为

| 测试文件 | 保护的行为 |
| --- | --- |
| `test_config.py` | manifest 与文件版本一致；四类配置的类型、完备性、数值、来源和历史 v1 重放例外 |
| `test_validation.py` | 静态 v1 contract 与 ConfigBundle 动态语义；ID、受控引用、真实日期、枚举、词表、类型/范围、unique/min-items、安全事件、跨字段及条件证据的契约矩阵 |
| `test_budget.py` | 建议预算可追溯；0.8/1.0 边界；风险缓冲封顶 |
| `test_matching.py` | 输入顺序不影响排名；必需技能、私密底线和边界是硬过滤 |
| `test_privacy.py` | 匹配说明不泄露私密底线；嵌套身份字段被拒绝 |
| `test_decisions.py` | 选择和反馈有效；被过滤者不能恢复；`OTHER` 需要说明 |
| `test_repository_and_reports.py` | 批量写入原子回滚；推荐快照不受资料更新影响；结果进入报告；Markdown/CSV 可生成 |
| `test_cli.py` | 导入整批预检、零写入、重复/空批次、错误隐私和成功顺序契约 |
| `test_schema_versions.py` | v1 根版本严格性；未知键/标签错误脱敏；公开 JSON Schema、runtime validator 与 Repository 对 required/unique/min-items、type/range/enum/date/ID/受控引用的一致性；current 损坏读 fail-closed；关闭的 safety-event 投影及零写入 |
| `test_contract_and_storage_invariants.py` | 固定跨字段 static invariants；legacy/current 的 SQLite 行元数据与 payload 身份一致性 |
| `test_migrations.py` | 纯且确定的 v0→v1 转换；closed demand resolution；withdrawn 映射；v1 identity 与未知版本拒绝 |
| `test_repository_migrations.py` | fresh v3 bootstrap；v0a/v0b exact DDL；current 受管 table 与全量 index/trigger 精确集合；未知吞写 trigger 拒绝；关闭强类型 plan parser；语义伪造拒绝；stale/rollback/幂等 |
| `test_cli_migrations.py` | canonical `--payload-schema`、同快照 status/dry-run 与 guarded apply、DB/payload 分轴；current `no_changes`；legacy gate；计划 0600；malformed SQLite/resolution 安全错误 |
| `test_migration_recovery.py` | staging→保留 descriptor 的备份、文件/目录 fsync 与复制后复验；不写/删替换 inode；restore inode 清理；流式 hash；worktree 拒绝；锁/commit-unknown；receipt/live 指纹分离；迁移历史 append-once |
| `test_migration_e2e.py` | legacy→v3/v1 切换后继续导入、列出、匹配，并产生显式 v1 推荐快照 |

## 风险驱动的测试金字塔

### 纯规则单元测试

对 validation、budget、matching、privacy 和 decisions 使用小字典构造边界。每条硬过滤至少需要“命中”和“接近但不命中”两个测试，尤其关注日期等号、金额等号、空列表、未知枚举和类型错误。

### 仓库集成测试

使用临时目录创建真实 SQLite，验证 schema 初始化、upsert/append 语义、外键、旧库迁移、快照、报告与删除工具。Repository 读取测试必须故障注入行元数据/payload 身份漂移；迁移结构测试必须变异类型、约束、索引语义和触发器定义，而不只删对象。迁移失败还要断言前后逻辑快照、备份目录、receipt/audit 与既存 inode，current no-change 必须证明 plan、备份、receipt 和数据库均零写入。测试不得写入默认 `mvp/local-data`。

### CLI 契约测试

`import` 已通过调用入口覆盖退出码、stdout/stderr、原子性和隐私；`migrate` 也直接覆盖 canonical flag、status、dry-run、apply、no-change、stale、legacy gate、关闭 plan/resolution、损坏文件和恢复退出码。resolution 中嵌套非字符串等错误必须只返回稳定代码，不输出原值、`TypeError` 或 traceback。其余业务子命令目前主要由函数测试间接覆盖。下一步应使用真实子进程验证全局参数顺序、文件不存在、非法 JSON、YELLOW 例外和所有子命令帮助。CLI 是运营脚本的接口，文字变化也可能破坏使用。

### 端到端样例

固定跑通 `init -> import -> validate -> budget -> match -> explain -> decision -> outcome -> report`。断言推荐 ID、候选顺序、过滤原因、报告关键指标和私密值均符合预期。

## 建议补充的测试

优先级从高到低：

1. 所有硬过滤代码的参数化边界测试；
2. 为未来逐行 `RetentionRunner` 单独设计法律删除、审计与推荐历史例外测试；
3. CLI 子进程退出码与 JSON 契约；
4. 自由文本中身份信息的人工/自动预检；
5. 新旧规则版本对同一历史批次的差分测试；
6. 报告在无推荐、无决定、退出/失败和重复结果下的行为；
7. 超过当前 MVP 数据量阈值时的备份耗时、空间与运营加密证据演练。

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

## 持续集成

独立 CI 在 pull request 和 `main` push 上运行：

```bash
(cd mvp && PYTHONPATH=src python3 -m unittest discover -s tests -v)
(cd platform && python3 -m pip install --disable-pip-version-check '.[test]')
(cd platform && PYTHONPATH=src python3 -m unittest discover -s tests -t . -v)
python3 scripts/verify_docs.py
```

2026-08-08当前受检平台快照中，Creator Profile既有19个contract、9个domain、10个application保持38/38；加IAM capability 5项与真实Profile PG18 13项为56/56。完整contract discovery为70/70；Demand IAM owner/reviewer direct-SQL为16/16，Demand PostgreSQL为17/17。真实PostgreSQL storage在只排除明确处于semantic RED的Taxonomy业务套件后为177/177。IAM head为16，Profile与Demand各使用独立head 1；测试发现catalog/manifest/pin中间态、SQL/fixture/ImportError或skip时必须报错，不能计作业务RED或稳定回归。

MVP 测试只依赖 Python 标准库。platform 的 `test` extra 锁定 YAML parser 与 psycopg binary；行为 CI 使用不可变 digest 的官方 PostgreSQL 18.4 Alpine service，并把仅测试的临时管理员 DSN 与 `DESIRE_IAM_TEST_POSTGRES_EPHEMERAL=1` 显式传给 harness。platform 核心库仍没有默认第三方运行依赖，部署 migration adapter 时必须安装并锁定 psycopg 3。Actions 使用固定提交 SHA。文档部署工作流先运行 MVP 测试与文档校验；行为 CI 另运行完整 platform suite。涉及行为变化的规则 PR 仍应补充新旧样例差分 artifact，待离线差分工具切片实现后接入。
