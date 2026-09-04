# INTERNAL_SANDBOX 容器部署

状态：仅限合成内部沙箱，`G1 NO-GO / G2 NO-GO`。本编排运行真实 PostgreSQL API
composition；它不批准真人研究、公开注册、真实合同、真实资金、真实权益决定或公网发布。

> 当前静态模式头为 IAM `0046`、Profile `0005`、Demand `0015`、Trust `0022`、Matching
> `0009`、Taxonomy `0002`，对应
> [Current-head v28 静态模式头](/operations/current-head-v28.md)。v28 前向修复 Matching ingest 名称歧义、coordinator 领取 scope/审计、reviewer claim 可见性/行锁、精确 CREATE 回执恢复与未来披露 UTC-Z 时间生成；
> 并为完成程序增加原选择意图回执的精确只读 policy。其余组件和合同保持原值。当前只读 gate 与版本化恢复入口分别为 `verify_current_head_v28.py` 和
> `postgres-operations-v28.compose.yaml`；静态校验不代表生产迁移、恢复演练或生产授权。
> 下文具体版本的动态记录保留原证据范围。冻结 v27/v26/v25 发布资产以及绑定当时 checkout
> runtime/source 的第 2.6 节 fresh-volume 本地合成验收继续分开记账；它们不能冒充 v27 或生产执行。冻结的 v24 发布资产及其
> 第 2.5 节本地合成动态验收彼此分开记账，不能冒充第 2.6 节或生产执行。冻结的 v23 发布资产与下列动态记录
> 继续分开记账；v23 发布资产仍是
> `STATIC VERIFIED / NOT PRODUCTION EXECUTED`；2026-08-26 此前 v21 对应的 IAM42/Demand11/Trust15 本地
> 合成动态验收已另行记账，见第 2.2 节；这不改变 `production_authorized=false`。v21/v20/v19 静态合同、下文
> v13 合同和 v12 运行记录都是保留的历史证据，不能冒充 v23 发布执行。2026-08-26 当时 checkout 曾在全新隔离本地栈动态运行到
> IAM `0041`、Profile `0003`、Demand `0011`、Trust `0014`、Taxonomy `0002`，并完成十账号、
> provider-only 邀请与停止/恢复持久性门禁；该历史本地证据单独记账，不改变 v23 的静态状态或
> `production_authorized=false`。
> IAM42/Demand12/Trust16 v22 runtime/source 的全新本地合成验收也已完成并作为冻结历史单独记账，见第 2.3 节；
> 当时的 v23 IAM42/Demand12/Trust17 runtime/source 随后也曾完成独立的 fresh-volume 本地合成动态验收，
> 见第 2.4 节；这仍不是生产 migration、发布执行或授权，冻结的 v23 发布资产继续保持
> `STATIC VERIFIED / NOT PRODUCTION EXECUTED`。
> 冻结的 v12 历史动态证据到
> IAM `0036`、Profile `0003`、Demand `0009`、Trust `0006`、Taxonomy `0002`；其输入根为
> `secrets/e2e-ten-account-v12/`，bundle 为
> `internal-sandbox-bundle-iam36-demand9-trust6`，image tag 为
> `e2e-ten-account-v12-iam36-demand9-trust6`，Compose project 为
> `desire-supply-e2e-ten-account-v12`，runner state 为
> `/private/tmp/desire-ten-account-e2e-state-v12.json`。十个账号覆盖八个职责；fresh migration、
> 第二轮 exact skip、唯一 journey 和两轮完整 restart 均已完成。唯一 journey 精确返回
> `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，两轮 restart 均精确返回
> `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`。migration/taxonomy/reconcile/verify/identity
> one-shot 的最终 JSON 日志条数精确为 `2/1/1/1/1`；两轮恢复都只使用
> `up -d --no-deps --no-recreate --wait`，没有重跑 one-shot。v10 journey 失败、v11 restart
> 无效，均保全为失败历史。不得把 v12/Trust6 证据写成 Trust7 动态证据。应用内 Browser 的隔离
> localhost 无法桥接宿主机 Docker loopback；第 2.6 节的历史 v25 checkout 尝试也复现连接关闭/站点不可达，
> 因此 current-head v27 的完整桌面/移动视觉 QA 仍未执行。两次历史尝试都未安装 CA trust 或绕过证书警告。
> v9/Trust5 逻辑 backup 与 fresh isolated-volume restore
> 已动态通过，但历史 Trust7 backup/restore、冻结 v22 IAM42/Demand12/Trust16 backup/restore 与
> 历史 v23 IAM42/Demand12/Trust17、冻结 v24、历史 v25 IAM42/Demand12/Trust18、冻结 v26
> IAM43/Demand13/Trust19 与 current-head v27 IAM46/Profile5/Demand15/Trust22/Matching3/Taxonomy2
> backup/restore、加密离机备份、定期恢复、PITR 与告警仍未完成。current-head v27 的只读静态 verifier
> 固定逻辑 backup/isolated restore 脚本、只含 aggregate counts 的 durable facts 与双 config overlay；
> 它们尚未执行，不能把“有当前入口”写成恢复演练 GREEN。入口与限制见 current-head v27 页。

## 1. 启动图与权限边界

`compose.yaml` 的关闭顺序为：

```text
synthetic-oidc healthy -> edge healthy ---------------------+
                                                            v
db healthy -> migrate -> taxonomy-seed -> online-credentials-reconcile
  -> online-credentials-verify -> identity-bootstrap -+-> api ready -> web healthy
                                                  \-> matching-runtime healthy
```

`migrate`、`taxonomy-seed`、`online-credentials-reconcile`、
`online-credentials-verify` 和 `identity-bootstrap` 是 one-shot deployment services。只有
deployment jobs 能读取 PostgreSQL superuser secret；API 只收到 deployment config pointer、
三份只读应用配置、只读 sandbox root CA 和精确 43 份 runtime secret：15 个 role-bound DB
credential 与 28 个 key carrier。独立 `matching-runtime` 只收到三份 Matching 配置和精确
11 份 runtime secret：5 个 role-bound DB credential 与 6 个 key carrier。两进程合并去重后的
bundle 边界是 19 个数据库 credential、34 个 key carrier，共 53 份 runtime material；共享的
`trust_decision` credential 只计一次，两个进程不得互相挂载对方的其余 secret。

API 不发布 host port，也不挂 superuser secret。只有 edge 发布 `127.0.0.1:443`；`app`、
`data` 和 `oidc-backend` 都是 internal network。合成 IdP 只在 `oidc-backend:8081` 明文监听，
edge 是唯一 TLS 终止点。API 在 `app` 网络通过 edge alias 访问
`https://identity.example.test`，仍执行标准 CA、hostname、discovery、JWKS 与 JWT 校验。

identity job 在同一 Python 进程内完成 manifest generate → digest 复核 → apply → verify；
动态 digest 不经 shell/命令行传递，digest-only 文件只写入容器 tmpfs。

固定的 PostgreSQL 18.4 镜像声明 `VOLUME /var/lib/postgresql`。`db` 必须继续把既有 named
volume 挂到 child `/var/lib/postgresql/data`，并保持
`PGDATA=/var/lib/postgresql/data/pgdata`；同时用参数
`rw,nosuid,nodev,noexec,size=1m` 的显式 tmpfs 覆盖 parent `/var/lib/postgresql`，避免
Docker 为镜像声明创建无 Compose labels 的匿名 parent volume。这个嵌套布局是兼容既有数据
volume 的安全边界；不得把 named volume 的 target 改到 `/var/lib/postgresql`。backup、
restore target 与 restore verify 中所有直接使用官方 PostgreSQL 镜像的服务也必须覆盖同一
parent；只有 restore target 继续持有 child named volume。

base 十一个服务、Dev Container、五个 PostgreSQL backup/restore 服务和真实 OIDC overlay 的
`oidc-egress-guard` 都在 resolved Compose 中固定同一有界日志合同：Docker `local` driver，
`max-size=10m`、`max-file=3`、`compress=true`。因此每个**新建**容器的 stdout/stderr 名义上限约为
30 MiB，实际磁盘占用还受 metadata、压缩和当前活动文件影响；这不是容量承诺。Docker 只在创建
容器时固定 `HostConfig.LogConfig`，已有或已停止容器不会因 checkout 中 YAML 改变而自动回填；
尤其不得为给冻结的历史证据“补日志策略”而 recreate。`stop`/受控 recover 保留同一容器及其
有界日志，删除容器、`down` 或 `rm` 会删除该容器的本机日志。本策略不是业务 Audit、集中采集、
告警、敏感数据擦除、PITR 或加密离机备份，应用仍必须遵守字段 allowlist。

## 2. 外部前置与静态门禁

目标主机需要 Docker Engine、Docker Compose、OpenSSL 和本地 Python/uv。从仓库根执行：

```bash
docker --version
docker compose version
uv --version
python3 -B scripts/verify_container_stack.py
python3 -B scripts/verify_current_head_v28.py
python3 -B -m unittest \
  tests.deployment.test_container_stack \
  tests.deployment.test_internal_sandbox_tls -v
python3 -B -m unittest tests.deployment.test_postgres_operations_v27 -v
```

静态验证必须输出 `{"status":"OK"}`，Compose/Caddy/TLS 契约必须 13/13 GREEN；v27 verifier
必须只输出 `{"status":"CURRENT_HEAD_V27_STATIC_VERIFIED"}`，且 v27 PostgreSQL operations 静态合同
必须 5/5 GREEN。该 verifier 与这些测试本身都不执行 migration 或 backup/restore；
第 2.2 节另行记录此前 v21 对应的 IAM42/Demand11/Trust15 本地动态结果，第 2.3 节冻结 v22
runtime/source 的本地合成结果，第 2.4 节记录历史 v23/Trust17 的 fresh-volume 本地合成结果，
第 2.5 节记录冻结 v24/Trust18 的独立 fresh-volume 本地合成结果；第 2.6 节另记历史 v25 checkout
runtime/source 的 fresh-volume 本地合成结果，但这些记录均不构成 v27 动态或生产执行。
2026-08-26 IAM41/Trust14
仍只作历史，且本地合成验收不能替代 current-head v27 生产发布执行、浏览器视觉 QA、
backup/restore 动态演练、PITR 或告警门禁。当前 v27 的版本绑定 backup/restore 静态入口已经通过
`deploy/postgres-operations-v28.compose.yaml` 签入并由当前 verifier 检查，但本节没有调用 Docker
或创建 artifact/恢复资源。

合成 OIDC 固定为 issuer `https://identity.example.test`、client ID
`desire-internal-sandbox`、callback
`https://pilot.example.test/v1/auth/oidc/callback`。宿主机必须把两个 hostname 都解析到
`127.0.0.1`；root CA 只能导入受控测试浏览器或当前用户 trust store。不得绕过证书警告、
关闭 hostname/JWT 校验、改用 HTTP、建立 tunnel 或发布公网。

### 2.1 历史：2026-08-26 IAM41/Trust14 本地动态证据

当时 checkout 已使用全新、隔离的本地试用栈完成一次动态验收；以下只记录去标识结果，不记录
项目名、临时路径、网络坐标、对象 ID 或认证材料：

- fresh migration 与五个 one-shot 全部 GREEN，IAM ledger 精确包含 `0..41`，管理器进入
  `HEALTHY`；
- 十账号旅程返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，并额外证明 ACTIVE Creator 接受第二
  authority 后保留原 `CREATOR` 与策略要求、User 版本精确加一、接受响应 `me` 等于随后
  `/v1/me`，User ETag 一致；
- provider-only 邀请旅程返回 `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`，pending 身份接受后
  只得到目标组织 `DEMAND_OWNER`；
- 同一栈受控 `stop → STOPPED → resume → HEALTHY` 后，restart verifier 返回
  `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`，没有重跑 one-shot；最终再次 `stop`，卷与全部资源保留；
- 首次隔离尝试动态暴露并保全了 IAM41 runner artifact assertion 缺项；补齐 `41` 映射并增加
  回归后，使用全新坐标完成上述结果。失败栈也只停止并保留，没有执行 `down` 或删除。

该历史结果证明当时本地 synthetic composition 可运行，不授予生产权限，不是 IAM42/Trust15
或 v21 动态证据，也没有完成视觉 QA、backup/restore、PITR、告警、加密离机备份或真实 OIDC 验收。

### 2.2 历史：v21 IAM42/Demand11/Trust15 本地动态证据（2026-08-26）

当时 checkout 已用全新、隔离、版本化坐标完成以下去标识本地证据；项目名、网络坐标、对象 ID、
认证材料和公开名称原值均不写入本文：

- [x] fresh 空数据卷从零应用 IAM `0..42`、Profile `1..3`、Demand `1..11`、Trust `1..15` 与
  Taxonomy `1..2`；migration、taxonomy seed、credential reconcile/verify、identity bootstrap
  五个 one-shot 均以 0 退出，五个持久服务通过健康门禁；
- [x] 十账号/八职责旅程返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`。ORG_ADMIN 公开名称更正执行
  首次写入与 exact replay；同一个未接受邀请通过 live join 立即显示新名称，而 Invitation
  ID/version/ETag/token 与 policy binding 保持不变；
- [x] 独立 provider-only 身份从 pending、无角色/关系/工作区开始，接受后只取得目标组织
  `DEMAND_OWNER`，完成 Demand create/replay/cancel/history，返回
  `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`；
- [x] 管理器完成 `HEALTHY → STOPPED → resume → HEALTHY → STOPPED`；恢复只启动启动收据绑定的
  五个既有持久容器，没有重跑 one-shot。restart verifier 返回
  `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`，并重新读取到更正后的组织名称；最终所有资源保留；
- [x] 首次隔离运行在公开名称写入处 fail-closed，定位到生产 IAM response validator 未登记已审查的
  `OrganizationSummaryDto`。事务未提交、栈只停止并保留；增加唯一 schema 白名单和正/负回归后，
  使用另一套全新坐标完成上述 GREEN 结果；
- [x] 真实 PostgreSQL 18 集成套件 364 项全绿；IAM42 的 canonical predicate、授权、OCC、幂等、
  同名拒绝、MFA/角色边界、审计隐私和邀请 live join 由该套件与 HTTP/application 回归共同覆盖；
- [ ] 本轮是 fresh 空卷，因此 IAM42 前存量组织行数为零，只证明零存量路径。当前 migration
  composition 已在取得 provisioning advisory lock 后、任何 role/password/catalog 写入前，以
  `REPEATABLE READ READ ONLY` 和固定 timeout 自动全量预检 `public_name`：逐值为 NFC、与精确
  trim 结果逐字相等、长度 1..160 Unicode code point，且不含 `Cc`/`Cf`；输出只有聚合计数。
  这次只读事务不与旧 API writer 组成同一事务，不能声明在线扫描到 IAM42 commit 的原子性；真实
  升级必须先停止并排空旧 API/worker 写入，确认没有 live writer，再在同一静默窗口运行 migration。
  异常必须先受控修复并重扫，migration 不得自动 trim/normalize，且不得禁用 CHECK、改 migration
  bytes、手改 ledger 或跳过 IAM42；即便 CHECK 是最终竞态门禁，也不能据此省略 writer quiescence；
- [ ] migration runner 的 exact replay 已由真实 PG18 集成测试证明，但本轮一次性 manager 没有重跑
  migration one-shot；生产 backup/restore、视觉 QA、PITR、告警、加密离机备份与真实 OIDC 仍须
  独立验收。

### 2.3 历史冻结：v22 IAM42/Demand12/Trust16 本地动态证据（2026-08-26）

当时的 runtime/source 代码（随后只新增去标识证据文档）已在全新隔离坐标完成：

- [x] fresh 空卷从零应用 IAM `0..42`、Profile `1..3`、Demand `1..12`、Trust `1..16`、
  Taxonomy `1..2`；五个 one-shot 以 0 退出，五个持久服务通过 `HEALTHY` 门禁；
- [x] 十账号旅程返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，覆盖八职责、ORG_ADMIN 公开名称、
  Finance Operator 临时 duty 配置/撤销，以及资金审查终态历史的分页、本人可见和 actor 隔离；
- [x] provider-only 身份从 pending 零权限只激活目标组织 `DEMAND_OWNER`，Demand
  create/replay/cancel/completed-history 返回 `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`；
- [x] `HEALTHY → STOPPED → resume → HEALTHY → STOPPED` 全链通过，resume 未重跑 one-shot；
  restart verifier 返回 `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`，Finance/Trust/Appeal/账号/组织
  持久事实均可重新读取；
- [x] 两次较早尝试分别 fail-closed 于“证据写入封存 input root”和“restart history stage 未登记”。
  前者现在在登录前拒绝直接路径和祖先 symlink 绕回，后者已加入封闭枚举与直接回归；失败栈与最终
  GREEN 栈都只停止并保留，未复用坐标、未执行 `down` 或删除；
- [ ] 本轮 fresh 空卷不能替代服务器存量 `public_name` preflight；backup/restore、完整视觉 QA、
  PITR、告警、加密离机备份与真实 OIDC 仍是独立门禁。

### 2.4 历史：v23 IAM42/Demand12/Trust17 本地动态证据（2026-08-26）

当时的 runtime/source 已在一套全新隔离的本地合成 fresh-volume 栈完成验收；最终 `STOPPED` 后只追加
去标识文档记录，应用、Docker、migration 与 runtime source 未再变化。本节不登记 root、project、
tag、CIDR、对象 ID 或认证 ID：

- [x] fresh migration 到达 IAM `0042`、Profile `0003`、Demand `0012`、Trust `0017`、Taxonomy
  `0002`；管理器从 `PREPARED` 进入 `HEALTHY`；
- [x] 十账号旅程返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，独立 provider-only invited Demand
  Owner 旅程返回 `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`；
- [x] `STOPPED -> resume -> HEALTHY` 后 restart verifier 返回
  `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`，且 `trust_terminal_history_discoverable=true`、
  `terminal_history_actor_scoped=true`；
- [x] 最终回到 `STOPPED`；精确保留十个容器、四个网络、一个 PostgreSQL volume 与三个应用镜像，
  全部容器 `RestartCount=0`；
- [x] 四份互异 evidence JSON 均为 `0600` regular file；全程未执行 `down`、删除、remove 或 cleanup；
- [ ] 这只是合成本地 fresh-volume 动态证据。真实存量 preflight、production migration/deployment、
  backup/restore、完整视觉 QA、PITR、告警、加密离机备份与真实 OIDC 仍是独立门禁；current-head v23
  页面继续保持 `STATIC VERIFIED / NOT PRODUCTION EXECUTED`。

### 2.5 历史冻结：v24 IAM42/Demand12/Trust18 本地动态证据（2026-08-26）

当时的 v24 runtime/source 已在另一套全新、隔离的本地合成 fresh-volume 栈完成验收；最终 `STOPPED` 后
只追加去标识文档记录。本节不登记 root、project、image tag、CIDR、对象 ID 或认证 ID：

- [x] fresh migration 到达 IAM `0042`、Profile `0003`、Demand `0012`、Trust `0018`、Taxonomy
  `0002`；管理器从 `PREPARED` 进入 `HEALTHY`，五个 one-shot 成功且五个持久服务健康；
- [x] 十账号旅程返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，独立 provider-only invited Demand
  Owner 旅程返回 `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`；
- [x] Appeal Reviewer 本人完成复核的 history list、终态 detail 与 completed task 均可发现；错误角色
  list/detail 返回 `404`，额外 query 返回 `400 INVALID_REQUEST`。临时第二 reviewer 只能看到空的本人
  history，读取第一 reviewer 的终态 detail 返回 `404`，随后 duty 已恢复原状；
- [x] `STOPPED -> resume -> HEALTHY` 后 restart verifier 返回
  `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`，并从保留数据库重新发现 Trust 与 Appeal 终态事实；
- [x] 最终回到 `STOPPED`；十个启动收据绑定的容器、四个网络、PostgreSQL volume、应用镜像与四份
  私有 evidence JSON 均保留；全程未执行 `down`、delete、remove、`--rm` 或 prune；
- [x] Platform `1929` 项、Web `200` 项（包含 production build）与 deployment `536` 项全绿；v24
  静态 verifier 与 103 页文档 verifier 也通过；
- [ ] 应用内 Browser 的隔离 localhost 无法桥接到宿主机 Docker loopback。临时 hosts 映射已逐字
  恢复，未安装 CA trust，也未绕过证书警告；完整桌面/移动视觉 QA 继续保持未完成；
- [ ] 这只是合成本地 fresh-volume 动态证据。真实存量 preflight、production migration/deployment、
  backup/restore、PITR、告警、加密离机备份与真实 OIDC 仍是独立门禁；冻结 current-head v24 页面
  保持原字节与 `STATIC VERIFIED / NOT PRODUCTION EXECUTED`，不能冒充 v25 动态证据。

### 2.6 历史：v25 checkout 本地合成动态证据（2026-08-26）

绑定 fresh manager source receipt 的 IAM42/Profile3/Demand12/Trust18/Taxonomy2 runtime/source 已在一套
全新、隔离的 fresh-volume 栈完成验收。最终 `STOPPED` 后只新增去标识文档；以下不登记 root、project、
image tag、CIDR、对象 ID 或认证 ID：

- [x] 五个 one-shot 成功、五个持久服务健康，管理器完成 `PREPARED -> HEALTHY`；
- [x] 十账号/八职责旅程返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，独立 provider-only invited Demand
  Owner 旅程返回 `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`；
- [x] 抽样查看的近期 live API boundary entries 只含低基数、字段闭合的 `HTTP_BOUNDARY_OBSERVATION_V1`；
  该样本不含 raw request target、query/header/body、actor/object/trace ID 或 exception text；manager live inspect 同时确认每个容器精确使用
  Docker `local` driver、`max-size=10m`、`max-file=3`、`compress=true`；
- [x] receipt-bound Web 的 production build 与 `206` 项测试、deployment `549` 项和 v25 静态 verifier
  全绿；未改动 Platform source 的 `1935` 项 GREEN 基线继续有效；
- [x] `STOPPED -> resume -> HEALTHY` 后 restart verifier 返回
  `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`，并重新发现 Finance、Trust、Appeal、Organization、account、
  Profile 与 Demand 终态；
- [x] 最终状态为 `STOPPED`。十个 receipt-bound 容器、四个网络、PostgreSQL volume、应用镜像与
  `0700` 目录内四份 `0600` evidence JSON 全部保留；未执行 `down`、delete、remove、`--rm` 或 prune；
- [ ] 应用内 Browser 无法桥接宿主机 loopback 的合成 HTTPS 服务，返回连接关闭/站点不可达。未安装
  CA trust、未绕过证书警告，也未改 hosts 或系统信任配置；完整桌面/移动视觉 QA 仍未完成；
- [ ] 这是本地 synthetic fresh-volume 证据，不替代真实存量 IAM42 preflight、production
  migration/deployment、backup/restore、PITR、告警、加密离机备份、真实 OIDC 或发布授权。
  冻结的 current-head v25 页面继续保持 `STATIC VERIFIED / NOT PRODUCTION EXECUTED` 与
  `production_authorized=false`；本节不是 current-head v26 动态证据。

## 历史 Current-head v13 production proof 合同（未执行）

本节保留 IAM37/Profile3/Demand10/Trust7/Taxonomy2 的历史未执行合同，只用于审计追溯；
冻结坐标简称 `IAM37/Demand10/Trust7`，其中 Trust 对应迁移 `0007`；它不能替代
`v12/Trust6` 动态证据。它不再是 current pointer，也不得在这些坐标上执行。当前合同只见
v26 页面。v13 始终只属于
`INTERNAL_SANDBOX`，不改变 `G1 NO-GO / G2 NO-GO`，也不是已生成的动态证据：

| 坐标 | 固定值 |
| --- | --- |
| Compose project | `desire-supply-e2e-ten-account-v13` |
| image tag | `e2e-ten-account-v13-iam37-demand10-trust7` |
| input root | `/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13` |
| bundle directory | `/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/internal-sandbox-bundle-iam37-demand10-trust7` |
| deployment ID | `sandbox-e2e-ten-account-v13` |
| release ID | `release-e2e-ten-account-v13-iam37-demand10-trust7` |
| ingress / OIDC / app / data | `172.16.227.0/24` / `172.16.228.0/24` / `172.16.229.0/24` / `172.16.231.0/24` |
| durable evidence root | `/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/e2e-evidence` |
| runner state | `/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/e2e-evidence/state.json` |
| journey result | `/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/e2e-evidence/journey-result.json` |
| restart results | `/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/e2e-evidence/restart-1-result.json` / `/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/e2e-evidence/restart-2-result.json` |
| backup leaf / basename | `/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v13drill01` / `v13-iam37-profile3-demand10-trust7-taxonomy2-drill01` |
| restore project / subnet | `desire-restore-verify-v13drill01` / `172.16.232.0/24` |

input root 必须是当前 UID/GID 所有、非 symlink 的真实 0700 目录。bundle
generator 的 `--output-dir`、`--deployment-id` 和 `--release-id` 必须精确使用上表
值，成功 JSON 中的 `output_dir` 也必须精确等于上表绝对 bundle 路径。
`compose.env` 只能指向这一 input/TLS/bundle 树，IPAM overlay 只能包含上表
四个互不重叠的 RFC1918 `/24`。durable evidence root 必须在 journey 前排他创建为
0700 真实目录；state 与三份 result 必须使用 runner 的 `--state-output` /
`--state-file` / `--result-output` 写入各自不存在的绝对路径，成功后都是单链接、
非 symlink 的 0600 regular file。这些是本机保全证据，不是加密或离机备份。

v13 只允许以下预先声明的消费顺序：

1. 在任何创建前，同时证明 project label namespace、container/network/volume 名称前缀、
   三个 image tag、四个 CIDR、input root、evidence 路径与 edge `127.0.0.1:443` 均未被占用；
   随后且仍在任何 v13 input/evidence 目录创建或 `compose_v13 build` 前，精确调用一次
   `python3 -B scripts/preflight_docker_hub_manifests.py`。该 invocation 必须让五个 production ref
   的三轮 HEAD（共 15 次）全部 GREEN；任一失败会使整次观察作废，程序内部不得重试，也不得把
   不同 invocation 的成功轮次拼接起来。若再次检查，只能从第一轮开始一组全新的完整 invocation；
   在某一组完整 GREEN 前不得创建或消费这组 v13 坐标。它只读取 manifest metadata，不拉取镜像
   层、不创建或启动容器；
2. 唯一 fresh build 后按依赖顺序初始化。首轮 migration 必须 exact apply IAM `0..37`、
   Profile `1..3`、Demand `1..10`、Trust `1..7`、Taxonomy `1..2`，所有 skipped 为空；
3. 首轮 migration GREEN 后，只直接启动同一个已退出的 `migrate` container 一次。这是预先声明的
   same-container exact-skip replay，不是失败重试；第二条 `SCHEMA_READY` 必须 applied 全空并
   exact skip 同一五域版本；
4. taxonomy seed、online credential reconcile/verify、identity bootstrap、API ready 和 Web healthy
   全部 GREEN 后，唯一执行 journey，精确写入上表 state/result 并返回
   `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`；
5. 按 `web` → `api` → `edge` → `synthetic-oidc` → `db` 停止，再按相反顺序使用
   `up -d --no-deps --no-recreate --wait` 恢复五个原 container；先证明所有 one-shot、network、
   volume、container ID 和 state 未漂移，再唯一执行 restart verifier 1 并写入
   `restart-1-result.json`；
6. 以完全相同的 stop/recover、快照相等与一次 verifier 规则消费 restart 2，写入
   `restart-2-result.json`；两轮都必须返回 `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`，
   migration/taxonomy/reconcile/verify/identity 日志条数始终为 `2/1/1/1/1`；
7. 只有上述 source proof 全部 GREEN 后，才能在同一 v13 project 上执行一次 retained
   logical backup，并同时证明 source DB/container/network/volume/image 零 recreation；
8. 只有 backup exit 0、restart 0、一条 `DATABASE_BACKUP_READY` 和三份非空 0600 artifact
   全部成立后，才能在上表 fresh restore project 执行一次
   `database-restore-target` → `database-restore-bootstrap` → `database-restore-verify` →
   `database-restore-replay` 链。verify 必须精确输出一条 `DATABASE_RESTORE_VERIFIED`，
   最终 replay 必须 applied 全空并 exact skip IAM `0..37`、Profile `1..3`、Demand `1..10`、
   Trust `1..7`、Taxonomy `1..2`。

从任一 v13 input/evidence 路径创建、production build、fresh container/network/volume 创建、
journey/restart 业务写入、backup parent/leaf 创建或 restore resource 创建开始，任一命令失败、
超时、输出形状不符或快照不等都会永久锁定该组 project/tag/input/bundle/evidence/CIDR/
backup basename/restore project 坐标。锁定后不得重试、停止、删除、重建、重命名、
`down`、`rm`、`run --rm`、清理 volume 或换一个 state/result 路径复用同一业务坐标。
唯一例外是上述已预先声明的 same-container migration replay 和两轮 persistent-service
restart；它们各自只能按合同消费一次。新尝试必须先获得新授权，再使用全新的版本化
坐标。

fresh source build 成功后必须立即固定 v13 `api` container 的 `.Image` ID，并证明
`desire-supply-platform:e2e-ten-account-v13-iam37-demand10-trust7` 当前仍指向同一 ID。从该时点
起禁止对该 tag 再次 build、pull、tag 或删除。restore 不得 rebuild；只能使用
`up -d --no-build --no-recreate database-restore-replay` 启动依赖链，并证明
`database-restore-bootstrap` 与 `database-restore-replay` container 的 `.Image` 都精确等于上述
source Platform image ID。这是证明 restore 重放与 source journey/backup 使用同一受审
Platform deployment 的必要条件。

> 以下第 3–6 节只记录 v12/Trust6 已完成的历史动态证据和保全命令；它们不是
> v13 的可执行指令，不得把 v12 的路径、heads、CIDR、tag、state 或日志写成 current-head
> production proof。

## 3. v12 输入、bundle 与 Compose 绑定

v12 输入树已经生成并验证，禁止对现有目录再次执行 create、原地补写或覆盖。它包含四份
deployment-only secret、TLS fixture，以及十个固定虚构账号的二十个 subject/email source：

- `access_admin_01`、`appeal_reviewer_01`、`creator_01`、`demand_owner_01`；
- `operations_reviewer_01`、`finance_operator_01`、`finance_operator_02`；
- `org_admin_01`、`trust_officer_01`、`trust_officer_02`。

这十个账号覆盖 `ACCESS_ADMIN`、`APPEAL_REVIEWER`、`CREATOR`、`DEMAND_OWNER`、
`OPERATIONS_REVIEWER`、`FINANCE_OPERATOR`、`ORG_ADMIN`、`TRUST_OFFICER` 八个职责。
两个 Finance 账号共享 Finance 职责，两个 Trust 账号共享 Trust 职责。identity source 只读
挂载给 identity job；不得替换为真人 locator。

该 v12 bundle 当时精确报告：

```json
{"database_credential_count":11,"key_count":24,"output_dir":"/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v12/internal-sandbox-bundle-iam36-demand9-trust6","secret_count":35,"status":"INTERNAL_SANDBOX_BUNDLE_CREATED"}
```

目录结构为：

```text
secrets/e2e-ten-account-v12/
  compose.env
  compose.ipam.yaml
  internal-sandbox-identity-sources/                    # 精确 20 个 source
  internal-sandbox-tls/root-ca.pem
  internal-sandbox-bundle-iam36-demand9-trust6/
    config/deployment.json
    config/runtime-config.json
    config/secret-manifest.json
    runtime-secrets/                                    # 11 DB + 24 carrier
```

Demand receipt 的两个逻辑用途都必须包含两个 carrier，并保持以下精确顺序：

1. active `2026-01`；
2. `VERIFY_ONLY` retained `2025-12`。

稳定文件名为 `key-demand-idempotency-v1`、`key-demand-payload-hash-v1`、
`key-demand-idempotency-retained-2025-12`、`key-demand-payload-retained-2025-12`。
runtime config、secret manifest 与数据库 `demand.receipt_key_policy` 的 active/retained tuple
必须逐项一致；API readiness 在接收请求前 fail-closed 校验。轮换必须创建新的版本化输入树、
bundle、release、tag 和 project，不能修改 v12。

`compose.env` 只保存绝对路径指针，不保存 secret 内容。当前值为：

```dotenv
DESIRE_IMAGE_TAG=e2e-ten-account-v12-iam36-demand9-trust6
DESIRE_DB_PASSWORD_FILE=<absolute-repository-root>/secrets/e2e-ten-account-v12/db_superuser_password.txt
DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE=<absolute-repository-root>/secrets/e2e-ten-account-v12/taxonomy_seed_workload_credential
DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE=<absolute-repository-root>/secrets/e2e-ten-account-v12/taxonomy_seed_receipt_hmac_key
DESIRE_IDENTITY_SOURCE_DIR=<absolute-repository-root>/secrets/e2e-ten-account-v12/internal-sandbox-identity-sources
DESIRE_INTERNAL_SANDBOX_TLS_DIR=<absolute-repository-root>/secrets/e2e-ten-account-v12/internal-sandbox-tls
DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR=<absolute-repository-root>/secrets/e2e-ten-account-v12/internal-sandbox-bundle-iam36-demand9-trust6
```

所有 Compose 读取必须绑定 base compose 与 v12 IPAM overlay：

```bash
compose_e2e() {
  docker compose \
    --project-name desire-supply-e2e-ten-account-v12 \
    --env-file "$PWD/secrets/e2e-ten-account-v12/compose.env" \
    -f "$PWD/compose.yaml" \
    -f "$PWD/secrets/e2e-ten-account-v12/compose.ipam.yaml" "$@"
}
compose_e2e config --quiet
```

新终端必须重新定义 wrapper；不得使用默认 project、旧 env、旧 bundle 或缺少 IPAM overlay
的 Compose 命令。v12 overlay 固定 ingress/OIDC/app/data 为 `172.16.215.0/24`、
`172.16.216.0/24`、`172.16.217.0/24`、`172.16.218.0/24`；不得改成旧 project 的网段。

## 4. 精确启动顺序与 one-shot 退出条件

本节记录 v12 已执行的顺序，仅用于审计。v12 已完成且必须保全；不得在 v12 重新启动
one-shot、重建容器、覆盖 state、重跑 journey 或重跑任一 restart verifier。

v12 的 fresh 启动顺序为：

```bash
compose_e2e build api web edge
compose_e2e up -d --wait --wait-timeout 120 synthetic-oidc edge
compose_e2e up -d --wait --wait-timeout 120 db

compose_e2e up -d --no-deps migrate
docker wait desire-supply-e2e-ten-account-v12-migrate-1
compose_e2e logs --no-log-prefix migrate

# 首次成功后曾直接启动同一固定容器一次取得 exact-skip；该动作已消费。
docker start desire-supply-e2e-ten-account-v12-migrate-1
docker wait desire-supply-e2e-ten-account-v12-migrate-1
compose_e2e logs --no-log-prefix migrate

compose_e2e up -d --no-deps taxonomy-seed
docker wait desire-supply-e2e-ten-account-v12-taxonomy-seed-1
compose_e2e up -d --no-deps online-credentials-reconcile
docker wait desire-supply-e2e-ten-account-v12-online-credentials-reconcile-1
compose_e2e up -d --no-deps online-credentials-verify
docker wait desire-supply-e2e-ten-account-v12-online-credentials-verify-1
compose_e2e up -d --no-deps identity-bootstrap
docker wait desire-supply-e2e-ten-account-v12-identity-bootstrap-1

compose_e2e up -d --no-deps --no-recreate --wait --wait-timeout 120 api
compose_e2e up -d --no-deps --no-recreate --wait --wait-timeout 120 web
compose_e2e ps -a
```

v12/Trust6 fresh migration 的首次 applied 集合精确为 IAM `0..36`、
Profile `1..3`、Demand `1..9`、Trust `1..6`、Taxonomy `1..2`，五个 skipped 集合都为空；
紧随其后的第二轮 applied 五项全空，skipped 精确为同一组版本。最终
migration/taxonomy/reconcile/verify/identity JSON 日志条数精确为 `2/1/1/1/1`。这些容器与
日志已冻结；禁止再次启动。已保全的 v9 历史证据对应 Trust `1..5`，不能拿它代替 v12。

one-shot 只有同时满足退出码 0 和固定标签才通过：

- migration：`SCHEMA_READY`；
- taxonomy fresh seed：`INTERNAL_SANDBOX_TAXONOMY_SEED_READY` 且 `replayed=false`；
- reconcile/verify：均为 `ONLINE_CREDENTIALS_READY`，role count 精确为 11；
- identity：`IDENTITY_BOOTSTRAP_ORCHESTRATION_READY`，fresh 为 `APPLIED`，verify 为
  `VERIFIED`。

任一 `BLOCKED`、退出码 78、缺失/不同标签、head 不一致或健康超时都必须停在当前阶段。
不允许在前置 one-shot 未逐项 GREEN 时用 `--no-deps` 越过门禁、给 API 挂 superuser、手工写
ledger/policy，或用删除容器/volume 制造“重试成功”。API/Web 只有在全部门禁完成后才用
`--no-deps --no-recreate` 启动，以防 Compose 反向重跑已退出依赖。

API ready 必须从容器内返回 HTTP 200，且 body 包含：

```json
{"deployment_mode":"INTERNAL_SANDBOX","external_participants":"DISABLED","g1":"NO-GO","g2":"NO-GO","status":"READY"}
```

该 v12 ready 证明当时五个 schema head、35-secret carrier graph、11 个数据库 login、OIDC、Demand
key policy、Trust6 assignment-discovery/assigned-object handler 与 taxonomy projection 同时
成立。运行中依赖退化时
`/health/live` 可以保持 200，但 `/health/ready` 必须转为 503 `NOT_READY`。

## 5. v12 journey、restart 与视觉边界

v12 runner 使用 root CA
`$PWD/secrets/e2e-ten-account-v12/internal-sandbox-tls/root-ca.pem` 和唯一 state
`/private/tmp/desire-ten-account-e2e-state-v12.json`。journey 已唯一执行一次并精确返回：

```text
TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN
```

它覆盖十账号/八职责 workspace 隔离、政策、Profile、Demand review/整改、Finance 双人确认、
ACCESS_ADMIN 生命周期、ORG_ADMIN 邀请/成员生命周期，以及 Trust/Appeal 独立闭环。state 已
存在；禁止覆盖、删除或以另一 state 路径在 v12 再次执行 journey。

随后已完成两轮完整的 `db synthetic-oidc edge api web` 停止/启动与持久事实读回；每轮均精确
返回：

```text
TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN
```

两轮均包括数据库停止，不能用 Web refresh 或只重启 API 代替。两份 restart verifier 也已各
消费一次；不得在 v12 再次执行。任何未来新 project 的 restart 复验必须读取同一只读 state，
不得改变或重新生成 journey 事实。

v12 两轮 restart 使用下列顺序；未来版本化 project 也必须只操作五个持久服务，并显式切断
Compose 的 `depends_on` 启动链：

```bash
compose_e2e stop web
compose_e2e stop api
compose_e2e stop edge
compose_e2e stop synthetic-oidc
compose_e2e stop db

compose_e2e up -d --no-deps --no-recreate --wait --wait-timeout 120 db
compose_e2e up -d --no-deps --no-recreate --wait --wait-timeout 120 synthetic-oidc
compose_e2e up -d --no-deps --no-recreate --wait --wait-timeout 120 edge
compose_e2e up -d --no-deps --no-recreate --wait --wait-timeout 120 api
compose_e2e up -d --no-deps --no-recreate --wait --wait-timeout 120 web
```

禁止用 `compose_e2e start api` 或 `compose_e2e start web` 做这项复验：Compose 会沿依赖链
重新启动已退出的 migration、seed、credential 与 bootstrap one-shot，污染 restart 证据。
每轮恢复后必须先证明五个 one-shot 的 `StartedAt`、日志条数与退出状态完全未变，再运行一次
`verify-restart`。v12 两轮前后日志条数都精确保持 `2/1/1/1/1`。

HTTP、runner 与 workspace 隔离证据不等于浏览器视觉 QA。本机 URL 安全策略下尚未完成受控
桌面/移动浏览器视觉检查；该项保持未完成，不得据 curl、health 或 runner 勾选。

## 6. 只读诊断、轮换与保全式停止

故障时只读检查：

```bash
compose_e2e ps -a
compose_e2e logs --no-log-prefix \
  migrate taxonomy-seed \
  online-credentials-reconcile online-credentials-verify \
  identity-bootstrap api web edge synthetic-oidc db
```

不得读取或打印 secret 内容。当前 v12 的 one-shot、journey 与两份 restart verifier 均已完成，
不执行任何复跑或
轮换。未来轮换必须在新的版本化 project 中先停 `web`/`api`，再依次 reconcile → verify，
两者都 GREEN 后才能恢复 API/Web；不能原地修改 carrier。

停止 v12 且保留全部证据时，只允许按叶子顺序：

```bash
compose_e2e stop web
compose_e2e stop api
compose_e2e stop edge
compose_e2e stop synthetic-oidc
compose_e2e stop db
```

这只停止五个持久服务，并释放 edge 占用的宿主机 `127.0.0.1:443`。必须保留退出的 one-shot
容器、network、`postgres-data` volume、state 与日志。对当前或失败 project 禁止执行
`down`、任何 volume 删除、container remove 或临时运行后自动删除容器的命令。

## 7. Backup/restore、PITR 与告警门禁

本节保留 IAM37/Profile3/Demand10/Trust7/Taxonomy2 的历史 v13 backup/restore 合同；其中的 pins、
project、basename 与“当前头部”字样都是冻结审计材料，不是 current v27 操作入口，也不能作为
IAM46/Profile5/Demand15/Trust22/Matching3/Taxonomy2 current-head v27、冻结 v26、历史 v25 或冻结 v24
的动态证据；v23/v22 动态证据也不能据此扩展。

以下历史 v13 backup/restore 工具合同固定
`EXPECTED_PINS='18|37|37|3|3|10|10|7|7|2|2'`，并精确绑定 IAM/Profile/Demand/Trust/
Taxonomy reviewed contract digests。core facts 必须恰好产生一个非空 JSON object；其连续性计数
覆盖 Demand/Trust/Appeal receipts、assignments、inbox、audit、outbox 与 Trust7 的 IAM/Demand
dependency hashes。restore 的 empty-target gate 也覆盖这些 durable 表。该静态 pin 前移不改写
2026-08-19 的 v9 drill01 动态事实；Trust7 的 backup/restore 动态演练必须在新的隔离 drill
project 里单独生成，不得复用 v12、v10/v11 失败 project 或任何既有 drill project。
这些 operations client 与 restore target 同样继承官方镜像的 parent `VOLUME`：三者都用
`rw,nosuid,nodev,noexec,size=1m` 的 tmpfs 覆盖 `/var/lib/postgresql`，restore target 仍把
named volume 挂到 `/var/lib/postgresql/data` 并保持
`PGDATA=/var/lib/postgresql/data/pgdata`。不得把 named volume 的 target 改到
`/var/lib/postgresql`，也不得删除 parent tmpfs 后接受隐式匿名 parent volume。

历史 v13 source backup 必须原位绑定既有 project
`desire-supply-e2e-ten-account-v13`：命令同时使用
`secrets/e2e-ten-account-v13/compose.env`、仓库根 `compose.yaml`、
`secrets/e2e-ten-account-v13/compose.ipam.yaml` 和
`deploy/postgres-operations.compose.yaml`，从既有
`desire-supply-e2e-ten-account-v13_data` network 访问已经 healthy 且仍挂载 named
`postgres-data` volume 的 `db`。启动前后必须锁定 db container、project/service labels、
StartedAt/restart count、network ID 和 volume CreatedAt；任一不等都按零 recreation/空库风险
停止。backup 目录固定为
`/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v13drill01`。必须按
`$PWD/backups`、`$PWD/backups/internal-sandbox` 的顺序逐层处理：每层若存在或是 symlink，
必须证明它是非 symlink 的真实目录且为当前 UID/GID、mode 0700；若 absent，只能精确
`mkdir -m 0700 --` 该层后重复同一验证。leaf 必须 absent 且非 symlink，再以相同 owner/mode
创建；不得递归 chmod/chown，也不得用未逐层证明的 `mkdir -p`。仓库根 `.gitignore` 与
`.dockerignore` 各有且只有一个锚定 `/backups/`，避免明文 artifact 意外进入
VCS 或 Docker build context；这种排除不是加密或 offsite 保护。唯一写动作是对同一个 source project
执行 retained `database-backup` 的 `up -d --no-deps --no-build --no-recreate`；只有 container exit 0、
restart 0、日志恰好一个 `DATABASE_BACKUP_READY`，以及三份非空 0600 artifact 同时成立才可
进入 restore。从任一 parent 或 leaf 创建开始，失败后不得重跑、删除或改写；该 v13 project、
固定 basename 与已产生 artifact 都作为失败证据锁定。

历史 v13 restore 的 preflight 必须自包含并 fail-closed：在 restore 段重新固定 current UID/GID，
再次证明 retained backup leaf 是当前 UID/GID 所有的真实非 symlink 0700 目录，并证明三份
artifact 都是非空、非 symlink、当前 UID/GID 所有的 0600 regular file。fresh project namespace
不能只靠人工查看列表：container、network、volume 必须先按 Compose project label 显式断言
为空，再分别按 container 的 project-hyphen 与 network/volume 的 project-underscore name prefix
显式断言为空。这样同名但缺少或带错误 Compose label 的既有资源也会阻断 restore；任何一项
非空或任一枚举失败，都不得 build 或 `up`，必须换新的、从未写入过的 restore project 坐标。

当前 restore verification network 必须保持 `internal: true`，并用
`${DESIRE_DATABASE_RESTORE_SUBNET:-172.16.232.0/24}` 显式给出一个 RFC1918 `/24`；不得设置
gateway、Compose `name` 或 `external`。默认网段只是当前宿主机的候选，不是通用保证。每次
fresh drill 前必须枚举 daemon default-address-pools、全部 Docker CIDR、宿主直连路由、
更具体路由以及全隧道 VPN 连接前后的路由表。只要与 Docker、LAN、VPN 或其他宿主路由重叠，就要
先通过 `DESIRE_DATABASE_RESTORE_SUBNET` 选择新的不重叠 RFC1918 `/24`，不能退回自动分配。

进入 restore preflight 前还必须重新证明保留的 v13 `api` container `.Image` 与
`desire-supply-platform:e2e-ten-account-v13-iam37-demand10-trust7` 的 image ID 都精确等于 fresh
source proof 已固定的 Platform image ID。restore 阶段不得执行任何 `build`、`pull` 或 `tag`；
必须使用 `up -d --no-build --no-recreate database-restore-replay` 让 Compose 唯一创建完整依赖链。
如果 tag 缺失、指向不同 ID 或 source `api` image 无法证明，必须锁定本次 drill 并停止，
不得用 rebuild “修复”。

恢复链现在以保留容器的 `database-restore-replay` 作为最终 one-shot：它只能在
`database-restore-verify: service_completed_successfully` 后运行同一当前 Platform deployment，
且只能读取 restore DB 的 superuser secret。`database-restore-verify` 日志必须单独证明
`DATABASE_RESTORE_VERIFIED`；随后 replay 日志必须单独证明 `SCHEMA_READY`、五个
`applied_versions` 全空，并 exact skip IAM `0..37`、Profile `1..3`、Demand `1..10`、Trust
`1..7`、Taxonomy `1..2`。`database-restore-bootstrap` 和 `database-restore-replay` 的 `.Image`
还必须都等于固定的 source Platform image ID。任何缺项、额外 apply、image 漂移、
`BLOCKED` 或非零退出都不构成恢复证据。

本机 drill 的 custom dump、facts JSON 和 manifest 仍是明文 artifact；`.sha256` 只是
未签名 SHA-256 完整性记录，不是加密、签名、MAC 或离机副本。在获得明确的
`recipient/KMS/tool/destination authority` 前，不得实现或宣称 encrypted/offsite backup；
该门禁仍等待有权操作者明确指定接收方、KMS、工具和目的地。

2026-08-19 已在独立 project `desire-restore-verify-v9drill01` 完成一次 v9 动态演练：backup
容器只连 external `desire-supply-e2e-ten-account-v9_data` 网络做协议级读取，不挂载 v9 volume；
restore 的三个服务只连 `172.16.205.0/24` 内部网络并使用全新 volume。artifact basename 为
`v9-iam36-profile3-demand9-trust5-taxonomy2-drill01`，结果精确为
`DATABASE_BACKUP_READY` 和 `DATABASE_RESTORE_VERIFIED`。恢复后五域 migration ledger 全量 exact
skip，去标识连续性聚合与 v9 源库一致；v9 DB 全程 healthy、restart 0。

drill01 的容器、network、volume 与三份 0600 artifact 都作为证据保留；禁止用同一 project 或
basename 重跑，也不得清理 v9 或任何失败 project。本次证据不等于加密离机备份、定期恢复、
PITR、告警或依赖高风险处置；这些仍是未完成门禁。本手册不提供任何 volume 删除命令。

## 8. 历史证据（不得作为当前操作说明）

v9 是 IAM36/Profile3/Demand9/Trust5/Taxonomy2 的历史 GREEN：唯一 journey、两轮 restart 和
一次独立 backup/restore drill 均通过。v10 fresh 初始化通过，但唯一 journey 在 Trust assignment
额外 query 的错误 envelope 门禁失败，state 未生成；v11 唯一 journey GREEN，但第一轮 restart
错误使用 Compose `start api`，沿依赖链把五个 one-shot 各重跑一次，因此 restart 证据无效。
v9/v10/v11 均原样保全，不得重跑、清理或冒充 v12。

历史 v5 使用 `secrets/e2e-seven-account-v5/`、bundle
`internal-sandbox-bundle-iam35-demand7`、tag `e2e-seven-account-v5-iam35-demand7`、project
`desire-supply-e2e-seven-account-v5` 和 state
`/private/tmp/desire-seven-account-e2e-state-v5.json`。它是 IAM35/Profile3/Demand7/
Taxonomy2、七账号/六职责、11 DB + 22 key = 33 secret 的历史堆栈，曾返回
`SEVEN_ACCOUNT_ORG_ADMIN_E2E_GREEN` 与两轮
`SEVEN_ACCOUNT_ORG_ADMIN_RESTART_GREEN`。旧六职责 IAM32/Demand6 与更早四角色结果同样只
作追溯。

这些历史 project、容器、network、volume、input、bundle 与 state 都必须保留；不得将其
旧路径、旧计数、旧 heads 或旧标签用于 v12 或 current-head v13，也不得把历史 HTTP runner
写成浏览器视觉 QA。
