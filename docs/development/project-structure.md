# 项目结构

## 仓库地图

```text
desire-supply/
├── .github/workflows/
│   ├── ci.yml                 # PR/main 的 Python 测试与文档门禁
│   └── deploy-docs.yml        # 校验并发布 docs/ 到 GitHub Pages
├── docs/                      # Docsify 文档站与系统设计
│   ├── architecture/          # 当前与目标架构
│   ├── development/           # 开发、测试、演进
│   ├── guide/                 # 新手入口
│   ├── operations/            # 运营概览
│   ├── reference/             # CLI、配置、发布参考
│   ├── index.html             # Docsify 静态入口
│   ├── _sidebar.md            # 全站导航
│   └── *.md                   # 原始平台/MVP设计决策
├── mvp/
│   ├── config/                # 冻结且版本化的业务规则
│   ├── operations/            # 真实批次运行手册与安全流程
│   ├── samples/               # 可提交的虚构 JSON
│   ├── schemas/               # demand/creator/outcome 机器可读 v1 JSON Schema
│   ├── src/desire_mvp/        # Python 应用实现
│   ├── templates/             # 11 份访谈、协议和复盘模板
│   ├── tests/                 # unittest 行为测试
│   ├── local-data/            # Git 忽略的 SQLite 与报告
│   └── pyproject.toml
├── platform/
│   ├── contracts/             # 各 Context 的 OpenAPI、领域/事件/provider JSON Schema
│   ├── src/desire_platform/
│   │   ├── identity_access/   # domain/application/ports/adapters/security
│   │   ├── creator_profile/   # Profile domain/application/ports；按TDD逐层实现
│   │   ├── demand/            # Demand domain/application/ports；按TDD逐层实现
│   │   ├── http/              # immutable HTTP contracts、IAM protocol kernel 与 ASGI adapter
│   │   └── outbox/            # 跨 Context delivery contracts 与 worker orchestration
│   ├── tests/                 # domain、authorization、contract、application TDD
│   └── pyproject.toml         # 目标平台包与锁定测试依赖
├── scripts/
│   └── verify_docs.py         # 文档导航和站内链接检查
├── idea.md                    # 最初问题陈述
└── README.md                  # 仓库入口
```

## 代码分层

### 接口层

`mvp/src/desire_mvp/cli.py` 是唯一应用接口，负责：解析参数、选择用例、组织错误、决定输出格式。它可以调用领域函数和仓库，但不应内嵌新的匹配公式或 SQL。

`__main__.py` 只把 `python -m desire_mvp` 转交给 `cli.main`；`pyproject.toml` 的 `mvp` console script 指向同一入口。

### 领域规则层

`validation.py`、`budget.py`、`matching.py`、`explanations.py`、`decisions.py` 和 `privacy.py` 承担业务规则。函数优先接收普通字典和显式配置，不在内部读取全局数据库或环境变量，使规则可以独立测试和复算。

### Schema 与迁移层

`schema.py` 是 `mvp/schemas/*-v1.schema.json` 的零第三方运行时镜像，负责显式资料版本、关闭字段边界、required/unique/min-items/type/range/enum/date/ID/受控引用，以及不依赖配置的固定跨字段 contract。普通 validator、Repository 当前读写和迁移目标共享这些不变量；动态 taxonomy、预算键和 reason code 仍在配置驱动的 validator 中。

`migration_support.py` 冻结当前数据库/资料版本、v0a/v0b 完整 DDL、migration descriptors、历史 append-once 触发器及稳定错误；`migrations.py` 包含纯 v0→v1 转换、关闭强类型 MigrationPlan/controlled resolutions、同快照 status/plan、SQLite 锁与单事务 apply，以及 staging→保留 descriptor、流式 hash、文件/目录 fsync、inode 所有权保护的备份/恢复。业务规则不得绕过这层猜测 legacy 版本，已发布 descriptor 只能追加，不能就地改写。

### 数据与投影层

`repository.py` 是常规 SQLite 访问边界；业务模块不直接执行 SQL。它执行静态 payload contract 和行元数据↔payload 身份核对，并验证受管 table 定义、全量 index/trigger 精确集合、registry/receipt chain 与推荐 manifest；未知 trigger 会改变写语义，因此不允许作为扩展。只有 `migrations.py` 可以在受控迁移事务中执行结构变更。`reports.py` 从 Repository 读取事实并构建批次读模型。`models.py` 的数据类用于明确函数结果，不承担持久化 ORM 职责。

### 配置层

`mvp/config/manifest.json` 决定当前活动文件。四个版本文件分别表达词表、匹配、预算和原因代码。配置不是随意参数，而是影响参与者机会的业务策略，变更需要证据、版本和测试。

### 目标平台 IAM 切片

`platform/src/desire_platform/identity_access/domain/` 保存无 I/O 的 Invitation、Policy/Consent 与 authorization 规则；`application/` 编排命令事务；`ports/` 定义 SafetyHold 等外部边界；`adapters/memory.py` 只为可控 application 语义和逐写点回滚提供 copy-on-write UoW；`security/cryptography.py` 统一版本化 digest、关闭 canonical request 与 Session CSRF 派生。Memory GREEN 不替代 PostgreSQL 约束、并发、RLS 或 COMMIT unknown 证据。

`platform/contracts/` 是各 Context 的 HTTP/领域/事件机器契约，`platform/tests/contract/` 验证关闭对象、引用、敏感字段、数据库访问 profile 与错误语义。IAM PostgreSQL 已采用forward-only v0–v16 catalog、review pin、真实PostgreSQL 18、FORCE RLS和固定repository；0015仅提供Creator Profile消费的IAM capability，0016仅提供Demand owner/reviewer capability。Creator Profile与Demand各有独立catalog、ledger/compatibility与review pin，绝不复用IAM版本轴。精确GREEN/RED边界见 [IAM PostgreSQL 首个持久化切片](/architecture/iam-postgresql-implementation.md)及各子切片设计。后续Context不得把表静默塞入IAM schema或compatibility view。

`platform/src/desire_platform/http/` 是框架无关 immutable request/response、固定 IAM route registry、protocol kernel 与原始 ASGI byte boundary；关闭解析、Origin/CORS/CSRF、稳定错误、cookie rotation、断线/超时和隐私协议见 [IAM HTTP transport 与 ASGI 边界](/architecture/iam-http-transport.md)。该目录不得直接查询数据库、动态解释 OpenAPI或把 request object 交给领域 handler。

`platform/src/desire_platform/identity_access/application/read_models.py`、`ports/read_models.py` 与PostgreSQL fixed repository是九个 IAM 公开读取的immutable application query边界；字段allowlist、状态过滤、stored selector current、keyset cursor、ETag/cache、query budget和corruption fail-closed协议见 [IAM read model](/architecture/iam-read-models.md)及[PostgreSQL实现](/architecture/iam-read-model-postgresql.md)。Memory与真实PG18语义已GREEN；正式HTTP presenter/composition/E2E仍planned。它不得写last-seen/expiry/audit/outbox，不得接收任意filter/SQL或返回raw row。

`platform/src/desire_platform/identity_access/application/policy_consent_commands.py` 与 `ports/policy_consent_commands.py` 是 `AcceptCurrentPolicies`/`GrantConsent` 的独立 SELF command边界；exact requirement reference、current bundle、User If-Match、Session evidence、generic PILOT consent派生与receipt/atomic fault协议见 [IAM 当前政策接受与 Consent 授予命令](/architecture/iam-policy-consent-commands.md)。strict Memory application已GREEN；不得从read handler或Invitation Accept复制隐式路径，也不得把Memory UoW冒充尚未实现的真实SELF PostgreSQL adapter或HTTP composition。

IAM identity linking、recovery与closure目前只有[权威后续设计](/architecture/iam-identity-linking-recovery-and-closure.md)，尚无production package或测试GREEN。实现时必须在IAM内创建独立application/ports/adapters，不能以通用User CRUD、email merge或operator SQL扩展现有authentication handler。

`platform/src/desire_platform/outbox/` 是跨 Context 的delivery边界；lease/fencing、至少一次、schema registry、ack unknown、consumer inbox与隐私协议见[跨平台 Outbox delivery worker 设计](/architecture/outbox-delivery.md)。application与PostgreSQL 18 persistence/consumer inbox已GREEN；真实broker、具体projection consumer和socket级provider E2E仍planned。该目录不能读取业务私密表补齐事件，也不能把本地fake当作broker证据。

### 目标平台业务 Context

Creator Profile与Demand已发布独立机器契约并完成domain/application Memory GREEN；Creator Profile PostgreSQL独立0001、六fixed writer、FORCE RLS、receipt/COMMIT/pool与完整MATCH_INPUT capture已在真实PG18取得GREEN，HTTP/composition仍planned；Demand PostgreSQL仍处于独立semantic RED。Matching机器契约、domain与Memory application已GREEN；Taxonomy机器契约11/11 GREEN，domain/application正在建立semantic RED。其他业务Context必须先以各自权威设计页冻结边界，再创建独立package、contract和测试，不能先建通用CRUD：

- [Taxonomy、受控代码与规则目录](/architecture/taxonomy-and-rule-catalog.md)
- [Creator Profile、版本与字段披露](/architecture/creator-profile.md)
- [Demand、不可变版本与审核/资金/匹配边界](/architecture/demand-lifecycle.md)
- [MatchingAttempt、MatchRun、业务 Invitation 与 Selection](/architecture/matching-invitation-selection.md)
- [Project、Agreement、Milestone 与 Delivery/Acceptance](/architecture/project-agreement-delivery.md)
- [Workspace、消息、输入请求与 FileVersion](/architecture/workspace-and-files.md)
- [Funding、Payment、Webhook 与对账投影](/architecture/funding-and-payment-projection.md)
- [Trust、SafetyHold、Dispute、Appeal 与 Review](/architecture/trust-safety-dispute-review.md)
- [Notification、模板、偏好与投递回执](/architecture/notification-and-communications.md)
- [Audit、Analytics、Outcome 与可观测性](/architecture/audit-analytics-observability.md)
- [数据权利、保留、法律保留与清除](/architecture/data-rights-retention-and-erasure.md)
- [Controlled AI Gateway、模型策略与人工确认](/architecture/controlled-ai-gateway.md)
- [Community、Contribution 与规则治理](/architecture/community-governance.md)
- [生产组合根、部署与运行控制](/architecture/production-composition-and-operations.md)
- [Web BFF、浏览器会话与前端产品壳](/architecture/web-bff-and-frontend.md)

## 文档与实现的关系

| 文档 | 主要事实来源 |
| --- | --- |
| 当前 MVP 架构 | `mvp/src/desire_mvp/` 与 tests |
| 输入与 schema 契约 | `mvp/schemas/`、`schema.py`、`validation.py` 与 schema tests |
| Schema 与存储迁移 | `migration_support.py`、`migrations.py`、`repository.py` 与 migration tests |
| 领域模型 | `repository.py`、samples、数据字典 |
| 匹配与预算 | `matching.py`、`budget.py`、config |
| 数据安全 | `privacy.py`、资料保护手册、实际运营控制 |
| CLI 参考 | `cli.build_parser()` |
| IAM 目标平台设计与机器契约 | `platform/contracts/`、`identity_access/domain/application/ports/adapters/`与`platform/tests/`；Memory、部分HTTP和真实PG18纵切片已GREEN，production composition/provider/完整E2E仍按追踪表planned |
| IAM HTTP transport | `docs/architecture/iam-http-transport.md`、`platform/src/desire_platform/http/` 与独立 semantic/ASGI tests；kernel/injected dispatcher `18/18` GREEN，真实 server/composition/presenters/E2E planned |
| IAM read model | `docs/architecture/iam-read-models.md`、`iam-read-model-postgresql.md`、application/ports/PostgreSQL repository与独立tests；Memory和真实PG18 fixed SQL/RLS GREEN，presenter/E2E planned |
| IAM policy/consent SELF commands | `docs/architecture/iam-policy-consent-commands.md`、`iam-policy-consent-postgresql.md`、Memory handler与PostgreSQL adapter、独立 contract/application/真实PG18 tests；历史RED保留，现application 11/11、contract 4/4、PG目标18/18 GREEN；HTTP presenter/composition/E2E planned |
| 跨平台 Outbox 投递 | `docs/architecture/outbox-delivery.md`、`platform/src/desire_platform/outbox/` 与独立delivery/storage tests；application与PostgreSQL persistence GREEN，真实broker/consumer E2E planned |

修改接口、配置、状态、不变量或目录时，应在同一变更中更新对应文档。`scripts/verify_docs.py` 只能发现结构问题，不能发现语义过期。

## 新功能应放在哪里

- 新的资料门槛：`validation.py`，并补充样例和验证测试；
- 新的静态资料字段/类型：先更新 `docs/` 契约，再同步 `mvp/schemas/` 与 `schema.py`，用 validator/Repository/迁移差分测试证明入口一致；
- 新的固定跨字段或存储身份不变量：放入 `schema.py` 或 Repository 单一边界，并在 `test_contract_and_storage_invariants.py` 同时覆盖正常读写与 legacy preflight；
- 新的不可协商边界：`matching.filter_candidate`、版本配置、原因说明和测试；
- 新的排序信号：先通过批次证据，再修改 `matching.py` 和新版本配置；
- 新的 CLI 用例：在独立领域函数/Repository 方法完成规则后，由 `cli.py` 编排；
- 新的存储查询：只加入 Repository；报告聚合保持只读；
- 新的资料或 SQLite 版本：追加 schema/migration 设计、descriptor、关闭 plan/controlled resolution、exact DDL、receipt/恢复测试和切换文档，不修改已发布迁移的含义或临时移除 append-once 防护；
- 新的真实运营动作：先更新 `mvp/operations` 和模板，不默认写成软件；
- 目标平台 IAM 行为：先更新 `docs/architecture/identity-tenancy-consent.md`/ADR/机器契约，再在 `platform/tests/` 取得语义 RED，按 domain → application → PostgreSQL/API/E2E 边界实现；
- 跨 Context 异步投递：先更新 `docs/architecture/outbox-delivery.md` 和 event schema，再在独立 application test 取得语义 RED，最后实现 worker → PostgreSQL fixed SQL/权限 → broker/consumer E2E；
- 其他目标平台Context：先更新其权威设计页与追踪表，在独立contract/domain/application测试取得有效RED，再实现Memory→PostgreSQL/RLS→HTTP/E2E；不能把planned设计混入已验证实现说明。

## 依赖原则

MVP核心库刻意保持零默认第三方运行时依赖。platform为真实PostgreSQL adapter精确锁定运行时`psycopg[binary]==3.2.13`，`test` extra锁定契约测试的`PyYAML==6.0.3`，并由`uv.lock`固化解析结果。引入其他生产或测试依赖前需要说明：标准库为什么不足、供应链与维护成本、许可、离线可用性、数据是否离开本机，以及如何测试和锁定版本。文档站使用固定版本CDN资源，但不承载任何真实项目数据。
