# 本机全部使用 Docker

这套入口用于 macOS Docker Desktop 的日常本机运行。宿主机只需要 Docker Desktop、系统自带的 shell 和浏览器；业务运行、Python/Node 依赖、PostgreSQL、证书生成、构建和初始化都在容器中执行。验收时少数只读仓库 verifier 使用 macOS 自带 python3 配合宿主 Docker CLI，不在宿主安装项目依赖。

平台保持 `INTERNAL_SANDBOX`，使用虚构账号和合成数据。下述日常本机环境与历史发布验收项目分别管理。

## 管理本次已运行的项目

本次运行项目为 `desire-workflow-20260904-verified`。每次打开新终端，先在仓库根目录明确指定项目：

```bash
export DESIRE_LOCAL_PROJECT=desire-workflow-20260904-verified
./scripts/docker-local.sh status
./scripts/docker-local.sh check
```

日常停止和恢复也在同一项目变量下执行 `./scripts/docker-local.sh stop` 与 `./scripts/docker-local.sh up`。
当前可直接打开[工作台](https://pilot.example.test)：两个本机域名映射和精确叶证书信任已由用户完成，
新项目复用了相同证书。`./scripts/docker-local.sh browser` 是可选的独立 Chrome 入口。

本项目输入位于 `.local/desire-workflow-20260904-verified/`，数据库卷为
`desire-workflow-20260904-verified_postgres-data`。原 `desire-workflow-20260904` 与
`desire-workflow-20260904-fixed` 保留各自失败证据；更早的 `desire-supply-local` 也保留。
省略项目变量会选中默认 `desire-supply-local`，不会自动找到本次项目。
同一时间只启动一个占用本机 443 的业务项目。

当前工作台覆盖画像、需求、运营审核、双人资金确认、组织/账号管理、Trust、Appeal 与 Matching。
资金确认后请求匹配仍需执行下文的显式 `match` 命令。尚无完整 Project、Agreement、里程碑交付/验收、
真实 Payment 或数据权利工作台；接受邀请不等于签约。实际通过范围与待完成项见
[Docker 验收记录](docker-workflow-acceptance-2026-09-04.md)和[浏览器验收记录](local-workflow-ui-acceptance-2026-09-04.md)。

## 在另一台机器首次启动

启动 Docker Desktop，在仓库根目录执行：

```bash
./scripts/docker-local.sh up
./scripts/docker-local.sh check
./scripts/docker-local.sh browser
```

未设置 `DESIRE_LOCAL_PROJECT` 时，首次 `up` 会构建镜像，创建 `.local/desire-supply-local/`，在无网络的临时容器里生成密码、TLS 证书、运行配置和账号来源，然后按依赖关系启动完整平台。首次构建需要联网下载仓库指定的镜像和依赖。已有本次项目无需重复初始化。

默认 Docker Desktop 项目名为 `desire-supply-local`；设定项目变量后使用指定名称。服务构成相同：

| 服务 | 用途 |
| --- | --- |
| `db` | PostgreSQL 18，数据保存在项目专用 named volume |
| `api` | Python API 与业务逻辑 |
| `web` | React Web 工作台与 BFF |
| `matching-runtime` | 后台匹配 worker 和 coordinator |
| `synthetic-oidc` | 本机虚构账号登录服务 |
| `edge` | Caddy HTTPS 入口，仅监听 `127.0.0.1:443` |
| 五个初始化任务 | 数据库迁移、分类种子、凭据配置/校验、十账号初始化 |

五个初始化任务显示 `Exited (0)` 是正常完成；六个常驻服务应显示 `healthy`。Compose 依据健康检查和初始化任务退出状态决定启动顺序，见 [Docker 官方启动顺序说明](https://docs.docker.com/compose/how-tos/startup-order/)。

## 打开工作台

`browser` 使用 `/Applications/Google Chrome.app` 打开独立的本机测试浏览器，访问 [工作台](https://pilot.example.test)。

该浏览器把 `pilot.example.test` 和 `identity.example.test` 解析到 `127.0.0.1`，为本次生成的叶证书公钥设置精确的 SPKI 允许项，并为此独立浏览器直接连接本机。它不需要修改 `/etc/hosts` 或安装系统 CA；浏览器数据位于所选项目输入目录的 `chrome/` 下（默认 `.local/desire-supply-local/chrome/`）。证书例外只用于该本机测试浏览器，行为依据 [Chromium 的 SPKI 证书允许项实现](https://chromium.googlesource.com/chromium/src/+/bff9ec6/services/network/ignore_errors_cert_verifier.h)。平时仍使用自己的普通浏览器。

首页点击登录，在合成身份提供方选择账号即可，不需要设置真实密码。例如：

| 账号 | 职责 |
| --- | --- |
| `creator_01` | 创作者 |
| `demand_owner_01` | 需求方 |
| `org_admin_01` | 组织管理员 |
| `operations_reviewer_01` | 运营审核 |
| `finance_operator_01` / `finance_operator_02` | 双人资金审核 |
| `access_admin_01` | 平台账号管理员 |
| `trust_officer_01` / `trust_officer_02` | Trust 审核 |
| `appeal_reviewer_01` | 申诉复核 |

首次登录按页面完成政策确认。详细业务操作见[运行与检查](/operations/run-and-check.md)。

## 资金确认后启动匹配

当前完整流程需要运营者显式启动一次 SYSTEM 工作流：需求方提交 → 运营审核通过 → 两名不同资金审核员确认 → 需求进入 `FUNDED` → SYSTEM 请求匹配 → 后台 worker 生成匹配结果 → 各角色继续在工作台处理邀请、审核和选择。资金二审完成后暂未自动调度这一步。

在仓库根目录执行：

```bash
./scripts/docker-local.sh match ORGANIZATION_UUID DEMAND_UUID EXPECTED_VERSION REQUEST_UUID
```

四个参数都是公开业务标识：组织 UUID、需求 UUID、资金确认后该需求的当前 aggregate version，以及本次操作新生成的 UUID。需求编辑器的 `GET /v1/app/demands/{需求UUID}` 响应中，`object_id` 是需求 UUID，`revision` 是这里的 `EXPECTED_VERSION`；不要使用内容版本号或资金审核 revision。组织 UUID 是当前组织工作区标识 `org:UUID` 中的 UUID。

可以在容器中生成一次请求 UUID，然后保留这次命令的四个参数：

```bash
docker run --rm --network none --entrypoint python \
  "desire-supply-platform:${DESIRE_LOCAL_PROJECT:-desire-supply-local}" \
  -c 'import uuid; print(uuid.uuid4())'
```

`match` 先在独立容器中配置或验证专用 `demand_system` 登录凭据，再在仅持有三种限定数据库登录和两种 Demand HMAC 密钥的容器中执行命令。专用文件保存在项目输入目录的 `workflow-secrets/`。业务命令校验真实 SYSTEM 权限、精确需求的已审核版本与 `SECURED` 资金事实，并通过正式规则目录和 Trust 决策读取当前证据；成功后由 Demand 的正常事务写入 request、回执、审计和 outbox。原始用户取自需求创建者，资金来源事件保留为因果引用。API 和后台 worker 不持有这份 SYSTEM 登录凭据。

成功输出 `status: MATCHING_REQUESTED`。后台 worker 随后消费事件；首次消费会发布已有的默认规则包。回到工作台刷新即可继续。命令遇到网络中断或 `COMMIT_OUTCOME_UNKNOWN` 时，用完全相同的四个参数重试；已完成操作返回 `replayed: true`，不会再创建 request 或事件。即使后来新增 SafetyHold，已完成回执仍可查询；新的操作仍须通过当前 hold 检查。

`PRECONDITION_FAILED` 表示需求 revision 已变化，先重新读取需求再决定是否发起新的操作；对同一需求改变原请求 revision 并复用请求 UUID 会返回 `IDEMPOTENCY_KEY_REUSED`。`SAFETY_HOLD_BLOCKED` 需要先按 Trust 流程处理。`match` 接受已具备资格的 `FUNDED` 或 `NO_MATCH` 需求，不提供跳过审核或资金确认的入口。

## 日常管理

```bash
./scripts/docker-local.sh status       # 状态，包含已完成的初始化任务
./scripts/docker-local.sh logs api     # 跟随 API 日志，Ctrl-C 退出查看
./scripts/docker-local.sh stop         # 停止平台与文档，保留数据
./scripts/docker-local.sh up           # 按健康依赖顺序恢复
./scripts/docker-local.sh check        # 校验证书、HTTPS 首页和登录发现端点
```

`up` 在首次成功后不会重跑初始化任务，也不会重建已有容器。常驻服务设有 `unless-stopped` 重启策略；Docker Desktop 重启后如有服务尚未就绪，再执行一次 `up` 等待按序恢复。

PostgreSQL 数据位于 `<项目名>_postgres-data`；本地密码、证书与配置位于 `.local/<项目名>/`，已被 Git 和 Docker build context 忽略。保留数据库时也要保留这份输入目录，不要重新生成密码。普通停机使用 `stop`，不要使用带 `--volumes` 的删除命令或 Docker Desktop 的卷清理操作。

若首次启动失败，先用 `status`、`logs` 查看具体失败服务；脚本会保留输入和数据库，并阻止自动重跑不完整的首次初始化。修复具体错误后可以按服务进行恢复，或使用新的项目名与未占用的网络创建另一套本机环境。

## 开发、测试和 MVP 也放进 Docker

```bash
DESIRE_LOCAL_PROJECT=desire-supply-local ./scripts/docker-local.sh dev-up
DESIRE_LOCAL_PROJECT=desire-supply-local ./scripts/docker-local.sh dev
```

上面每条命令显式选择本次已有的 `desire-supply-local-dev` 开发项目，不改变终端中用于管理业务项目的变量。
`dev-up` 复用现有 `compose.dev.yaml` 与 Dockerfile 的开发镜像；通常开发项目名是所选业务项目名加 `-dev`。
它使用自己的测试数据库、数据库密码、网络和依赖卷。开发测试不会连接工作台的数据库。

进入开发容器后可运行：

```bash
# 礼宾式 MVP：安装已在 dev-up 中完成
cd /workspace/mvp
uv run --offline --locked python -m unittest discover -s tests -v

# Platform
cd /workspace/platform
uv run --offline --locked --extra test --extra server pytest

# Web
cd /workspace/web
npm run typecheck
npm run lint
```

Python 虚拟环境、`node_modules`、uv/npm 缓存均在 Docker named volumes 中；源码通过 `/workspace` 挂载，编辑后立即可被开发命令读取。`dev-up` 本身不启动热更新 Web/API；上面的完整工作台使用构建后的镜像。

```bash
DESIRE_LOCAL_PROJECT=desire-supply-local ./scripts/docker-local.sh dev-status
DESIRE_LOCAL_PROJECT=desire-supply-local ./scripts/docker-local.sh dev-stop
```

平台和开发环境分别停止；只运行工作台时无需启动开发容器。

## 文档预览

```bash
./scripts/docker-local.sh docs
```

打开 [本机文档](http://localhost:5174)。HTTP 服务在容器中运行，只读挂载 `docs/`，修改文档后刷新即可。文档页面引用的 CDN 资源仍需要浏览器联网。

## 更新源码与新建环境

日常 `up` 是恢复命令，不会自动把代码修改部署到现有数据库。试用新 checkout 或涉及数据库模式升级时，用全新的项目名和未占用的四个 `/24` 网段：

以下四个网段仅为格式示例，已被本机保留的历史项目占用；执行前必须全部替换为实际未占用的网段。

```bash
./scripts/docker-local.sh stop
export DESIRE_LOCAL_PROJECT=desire-supply-local-next
# 下列四个示例网段必须替换，不能原样复制执行。
export DESIRE_LOCAL_INGRESS_SUBNET=172.29.244.0/24
export DESIRE_LOCAL_OIDC_SUBNET=172.29.245.0/24
export DESIRE_LOCAL_APP_SUBNET=172.29.246.0/24
export DESIRE_LOCAL_DATA_SUBNET=172.29.247.0/24
./scripts/docker-local.sh up
```

新项目使用新的数据卷与输入目录；后续终端需要设置相同的 `DESIRE_LOCAL_PROJECT` 来管理它，网段已保存到该项目的输入文件。`443` 同时只能由一个本机平台占用。默认四个网段为 `172.29.240.0/24` 至 `172.29.243.0/24`；初始化时可通过上述变量替换，尤其要避开已有 Docker 网络和 VPN/局域网路由。

生成的 TLS 叶证书有效期为 14 天、根证书为 30 天。这是短期本机测试配置；需要长期保留同一环境时，应另外安排证书更新，不能通过重新 `init` 覆盖已有密钥和数据库配置。
