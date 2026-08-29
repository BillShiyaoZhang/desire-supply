# G1 工程基线候选证据（2026-08-12）

> 证据 ID：`EVD-G1-ENG-20260812-01`
> 对应 Gate：`G1-08`
> 采集日期：2026-08-12（Asia/Shanghai）
> 结论：`UNVERIFIED — NOT A FIXED REVISION`
> 状态层：`UNVERIFIED`
> 范围：本地工作区、合成数据与隔离测试；不包含真人、真实产品数据、真实合同或真实资金

## 1. 这份证据能说明什么

本轮已经开始重采测试、分发、运行时和已知风险事实，并取得一组可重复的本地结果。它可以作为 G1 总评审的**候选输入**，但还不能使 `G1-08` 变成 `PASS`：仓库 `HEAD` 为 `8a09873013c937b139b322b82a2aea31307e8f4a`，而 `platform/` 与 `.github/workflows/ci.yml` 均为未跟踪内容；`git ls-files platform` 和 `git ls-files .github/workflows/ci.yml` 都返回 **0 个已跟踪文件**。因此这些结果尚未绑定到可检出的固定 revision。

本页也不改变[创始人定向 G1 构建决定](/foundations/g1-direct-build-decision.md)的证据边界。代码和测试通过不会把候选 ICP、问题、付费意愿、可用性或制度效果从 `E0` 升级，也不会授权 G2 的真实运行。

## 2. 本地环境事实

| 项目 | 观察值 | 解释 |
| --- | --- | --- |
| Git branch / HEAD | `main` / `8a09873013c937b139b322b82a2aea31307e8f4a` | `platform/` 不属于该 revision |
| uv | `0.9.15` | 本地测试工具，不是发布证明 |
| Python | `CPython 3.14.1` | 仍须在声明支持的版本矩阵重跑 |
| PostgreSQL 客户端/二进制 | `18.4` | `127.0.0.1:5432` 无服务响应 |
| 外部 provider | 只有 fake 或 Protocol 边界 | 无真实 OIDC、支付、通知、文件或 broker 组合证据 |

## 3. 已通过的本地测试

以下命令使用 `uv run --frozen --extra test`，明确排除了需要真实 PostgreSQL 的 `tests/storage/postgres`。HTTP 套件额外把 `tests` 加入 `PYTHONPATH`，以满足其既有 support import 约定。

| 套件 | 结果 |
| --- | ---: |
| application | 166/166 |
| authentication | 22/22 |
| authority lifecycle | 39/39 |
| authorization | 10/10 |
| contracts | 70/70 |
| CompleteSelection coordination / producer bridge | 22/22 |
| creator profile | 19/19 |
| demand | 11/11 |
| HTTP | 52/52 |
| matching domain | 16/16 |
| packaging clean install | 3/3 |
| policy / consent | 15/15 |
| read models | 11/11 |
| runtime | 26/26 |
| taxonomy | 10/10 |
| unit | 11/11 |
| **合计** | **503/503** |

文档校验另行通过：77 个可导航页面、内部链接、本轮 G1/G2 边界及 CI 非发布断言均通过。该数字不计入上表的软件测试总数。

## 4. 本轮新增的 Slice 0 证据

### 4.1 可安装分发工件

- canonical contracts 已收敛到 Python package 内，仓库级旧路径只保留相对兼容链接；
- wheel 与 sdist 分别在隔离环境安装，使用 `importlib.resources` 逐字节核验 23 份合同、4 份迁移 manifest 和 manifest 引用的 20 份 SQL；
- IAM、Creator Profile、Demand 与 Taxonomy 的迁移资源均包含在安装包内。
- PEP 517 构建后端固定为 `setuptools==80.9.0`，测试同时核验 wheel 记录的 generator，避免构建工具浮动；构建子进程显式移除源码测试使用的 `PYTHONPATH/PYTHONHOME`，防止源码包名遮蔽隔离环境标准库。

这关闭了“源码 checkout 可读、安装包缺少权威合同/迁移”的局部缺口；它没有证明服务器可以启动或数据库迁移已在真实 PostgreSQL 成功。

### 4.2 运行时健康边界

- 新增 `/health/live` 与 `/health/ready` 的框架中立 ASGI 边界；
- readiness 每次重新检查 pool、component 与 entrypoint；任一异常或开放式返回值都 fail closed；
- 依赖失败时为 `NOT_READY`，进程仍可保持 `LIVE` 以便编排器和人工诊断；关闭后两者均为 503；
- 响应固定为最小 `no-store` JSON，不序列化内部异常或 secret。

这形成 7 个新增健康验收测试；另有 5 个 package artifact 验证测试钉死 allowlist、digest、路径和错误泄露边界，连同已有 runtime 测试为 26/26。当前仍缺 concrete production bindings 与真实 server boot，不能称为可部署入口。

### 4.3 Matching attempt / Selection 隔离

新增规范 `selection-invitation-set-json-v1` 与事件 `SelectionInvitationSetChanged`。选择集合 hash 只覆盖同 attempt、同当前 run、已发布且对 selector 可见的 Invitation；`CREATED` 不进入集合。发布、接受或拒绝导致状态快照变化时，在同一事务刷新 Selection hash/version，并为该 Selection 变化写事件；跨 attempt/run 或重复成员失败关闭。

另有回归测试证明：发布某个 MatchingAttempt 的邀请时，不得复用另一个 attempt 的 Selection。

新增的 `CompleteSelection` 组合原语覆盖 SYSTEM + original actor 双授权、同 run/current ACCEPTED、Demand/Funding 精确绑定、Selection/Attempt/Demand/Project/Agreement 单次事务、11 个 checkpoint 回滚、唯一冲突与 commit-unknown 全链恢复。审查后又补上锁等待后的 UTC 时间/双授权重验、当前 Invitation 集合的同一规范 hash 重算、selector grant 精确版本绑定，以及完整 receipt/intent/trigger recovery chain。

真实 `ChooseCreatorHandler` 现在会在同一 Memory UoW 中持久化关闭的 `ChooseReceiptFact`、`SelectionIntentFact` 与不可变 pending trigger；Memory composition 验证该 trigger 可被 coordinator 消费，首次只创建一个 Project/Agreement，Choose 与 CompleteSelection 再次调用都收敛为重放。Matching/coordination 合计新增及回归为 application 166/166、coordination 22/22。

这些结果关闭了内存应用层的若干跨 attempt/run、stale hash 与 producer-trigger 缺口，但 Matching 尚无 PostgreSQL adapter；`CompleteSelection` 仍未接各 owning context 的正式事件 adapter/schema validator 或 PostgreSQL UoW。因此 production binding 与 context-event binding 的可用性标志继续为 `False`，相关 `Critical` 不能整体关闭。

### 4.4 CI 候选门禁

- Foundations、Platform 与当前合成 Demo 分为三个只读验证 job；旧 MVP 不作为新设计的阻断门禁；
- Platform 对声明支持边界 Python `3.9.6` 与 `3.14.1` 建立矩阵，每个版本都使用 digest-pinned PostgreSQL 18.4 跑分发测试与完整 suite；
- Action revision、Python/Node/uv、PostgreSQL image、lock 与 build backend 均固定；CI 契约测试拒绝 deploy、publish、artifact upload 与 OpenAI Sites；
- 本机无法执行这两个环境中的完整外部 PG18 组合，workflow 也仍未进入 fixed revision，所以这是候选门禁而不是 CI 已通过证据。

## 5. PostgreSQL 与安全基线仍未通过

本机 PostgreSQL 18.4 没有运行中的服务，本轮没有产生完整 PG18 套件的新绿色结果。此前同一任务的诊断曾观察到完整 discovery 的 PostgreSQL 语义失败和临时实例资源耗尽；该观察只用于确定阻塞，不作为本页的当前测试统计。

尤其仍须完成并证明：

- IAM 0017 的 Session replay / family convergence，以及轮换、CSRF、RLS 和连接池恢复语义；
- Demand 与 IAM PostgreSQL fixed-UoW 的真实事务结果；
- Matching PostgreSQL persistence、RLS、attempt/selection 隔离与完整选择协调；
- 从空 PostgreSQL 18 数据库安装全部迁移、重复执行、checksum/ledger 和 commit-unknown 恢复；
- 备份、恢复、回滚、连接清理和 provider timeout/replay 演练。

所以 PostgreSQL、Session 与跨租户正确性相关风险继续按[风险登记册](/foundations/risk-decision-and-assumption-register.md)保持 `BLOCKER`。

## 6. 使 G1-08 可评审的关闭条件

`G1-08` 至少需要以下证据齐备后才可提交总评审：

1. 将获批的 `platform/`、CI、合同、迁移与测试纳入一个可检出的固定 revision，并记录 source/artifact digest；
2. 在受控 PostgreSQL 18 服务上从空库运行完整套件，保存原始日志、失败清单与环境版本；
3. clean wheel/sdist install、迁移、server boot、`live/ready`、graceful shutdown 与恢复 smoke 全部从安装工件执行，而非依赖源码路径；
4. 对 Session、RLS、Matching 和迁移 Critical 给出关闭或 Gate 前控制证据，残余影响不再为 Critical；
5. 由 Engineering、Security 与独立 reviewer 具名确认 revision、证据日期、适用范围和失效触发。

在这些条件完成前，结论保持：**本地 Slice 0 有增量证据；`G1-08` 为 `UNVERIFIED/TBD`；G1 总状态仍为 `NO-GO`；G2 仍为 `NO-GO`。**
