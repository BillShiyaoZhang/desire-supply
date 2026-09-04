# 本地运行与逐步操作检查指南

状态：`INTERNAL_SANDBOX / SYNTHETIC ONLY`
复验日期：2026-08-29
适用范围：制度 Demo、本地七角色合成 API、真实 Docker API composition 与 Dev Container。

当前 IAM47/Profile5/Demand15/Trust23/Matching10/Taxonomy2 的静态模式合同见
[Current-head v29 静态模式头](/operations/current-head-v29.md)。current-head v29 前向修复 Matching
ingest 名称歧义、coordinator 领取 scope/审计、reviewer claim 可见性/行锁、精确 CREATE 回执恢复与未来
披露 UTC-Z 时间生成，以及完成程序对原选择意图回执的精确读取；当前只读 gate 为
`scripts/verify_current_head_v29.py`，版本化备份/恢复入口为
`deploy/postgres-operations-v29.compose.yaml`。静态检查不代表生产迁移、backup/restore 演练或生产授权。
本页其余标注具体版本的验收段落保留该版本的历史记录。历史
[Current-head v27 静态模式头](/operations/current-head-v27.md)、
[Current-head v26 静态模式头](/operations/current-head-v26.md)、
[Current-head v25 静态模式头](/operations/current-head-v25.md)、
[Current-head v24 静态模式头](/operations/current-head-v24.md)、
[Current-head v23 静态模式头](/operations/current-head-v23.md)、
[Current-head v22 静态模式头](/operations/current-head-v22.md)、
[Current-head v21 静态模式头](/operations/current-head-v21.md)、
[Current-head v20 静态模式头](/operations/current-head-v20.md)、
[Current-head v19 静态模式头](/operations/current-head-v19.md)、
[Current-head v18 静态模式头](/operations/current-head-v18.md)、
[Current-head v17 静态模式头](/operations/current-head-v17.md)、
[Current-head v16 静态模式头](/operations/current-head-v16.md)、
[Current-head v15 发布资产](/operations/current-head-v15.md)、
[Current-head v14 发布资产](/operations/current-head-v14.md)、下方 v13 与动态证据正文保持冻结；
current pointer 不会把它们改写为 v27、Demand15、Trust22 或 Matching3 运行结果。2026-08-25
曾有一次当时 checkout 的本地动态验收运行到 IAM40/Trust13；它与 v19、v20 静态资产分开记账，
现作为明确的历史动态证据保留，不把 `STATIC / NOT EXECUTED` 的发布声明改写为已发布或已获生产授权。
2026-08-26 当时 checkout 又在全新隔离栈完成 IAM41/Trust14 migration、十账号旅程、
provider-only 邀请旅程与停止/恢复持久性验收；它同样作为历史动态证据单独记账，见第 4.6.2 节。
此前 v21 对应 IAM42/Demand11/Trust15 的本地动态证据已于 2026-08-26 完成，见第 4.6.3 节；它不把
任何静态发布资产改写为生产发布，也不改变 `production_authorized=false`。
IAM42/Demand12/Trust16 v22 runtime/source 代码也曾在全新隔离栈完成十账号、provider-only
邀请与保留式重启验收，见第 4.6.4 节；该结果现作为冻结历史保留，不构成 v23/Trust17 动态证据、
生产执行或授权。
当时 IAM42/Profile3/Demand12/Trust17/Taxonomy2 v23 runtime/source 随后完成了一次独立的本地合成
fresh-volume 动态验收，见第 4.6.5 节；它与 current-head v23 的
`STATIC VERIFIED / NOT PRODUCTION EXECUTED` 发布声明分开记账，不构成生产执行或授权。
当时 IAM42/Profile3/Demand12/Trust18/Taxonomy2 v24 runtime/source 也已完成另一套全新隔离坐标的
本地合成 fresh-volume 动态验收，见第 4.6.6 节；它现为冻结历史，不能冒充 current-head v25 或 v26 执行。
当时 v25 checkout 的 runtime/source 随后也在全新隔离坐标完成十账号、provider-only、隐私安全日志与
停止/恢复持久性验收，见第 4.6.7 节；它现为历史 v25 动态证据，不能冒充 v26 或 v27。
current-head v27 静态发布仍保持 `NOT PRODUCTION EXECUTED`。

真实外部 OIDC 另有一份默认 inactive、不可激活的九服务静态叠层；它只用于关闭式配置审查，
不能替代本页的 synthetic 验收或现有私服激活器。见
[私有服务器真实 OIDC 静态配置](/operations/private-server-real-oidc.md)。

> Docker 已接入真实 PostgreSQL/OIDC/editor composition，不再使用 placeholder；合成
> OIDC、离线 TLS/CA 与双 hostname 也已接入 Compose 并通过静态契约。当前数据库模式头已经
> 静态前移到 IAM `0046`、Profile `0005`、Demand `0015`、Trust `0022`、Matching `0003`、
> Taxonomy `0002`。IAM46 提供 Creator authority 与 Profile eligibility resolver；Profile5 提供派生
> Matching 输入的不可变捕获；Demand15 增加固定 workload delivery、完成与零选择关闭；Trust22 对
> IAM46/Demand15 做 migration-honest repin；Matching3 提供确定性 worker/coordinator、selector 与
> reviewer 分配/释放及 durable 零候选关闭。IAM43/Demand13/Trust19 现在只属于冻结 v26。IAM42 保留
> ORG_ADMIN 公开名称更正边界，Demand12 加入 FINANCE_OPERATOR 本人完成资金审查历史，Trust18 新增
> APPEAL_REVIEWER 本人完成复核的 actor-bound、party-safe history/detail；Trust17 把
> Trust11 已冻结的 actor-bound、party-safe 本人完成案件历史发布到
> `/v1/app/trust/history`、task discovery、Web 与 restart 验收；Trust16 的 metadata-only repin 只作历史。
> IAM41 canonical Me、ACTIVE User 版本失效和 IAM40 PENDING_ENROLLMENT 精确邀请闭环继续保持；
> Demand11 与 Trust11 的本人完成历史也继续保留。current-head v27 发布资产仍未生产执行；历史 v25
> checkout 的本地合成验收见第 4.6.7 节，当时 v24 runtime/source 的独立 fresh-volume 动态验收见
> 第 4.6.6 节，v23 已完成的历史
> 动态验收见第 4.6.5 节，较早的 IAM42/Trust15 动态证据仍按历史另行记账。
> 2026-08-25 当时 checkout 已另行完成一次全新本地栈的 IAM40/Trust13 migration、十账号旅程、
> provider-only 邀请 Demand Owner 旅程及停止/恢复持久性验收；本页第 4.6.1 节记录其去标识结果。
> 2026-08-26 当时 checkout 的 IAM41/Trust14 动态结果见第 4.6.2 节。两者都是与静态发布资产
> 分开记账的历史本地动态证据，不是 current-head v19、v20、v21、v22 或 v23 的发布执行记录；此前
> v21 对应的 IAM42/Trust15 本地动态结果见第 4.6.3 节，同样不构成生产发布执行。
> 冻结 v22 runtime/source 代码的本地合成动态结果见第 4.6.4 节；它与 v22 的
> `STATIC VERIFIED / NOT PRODUCTION EXECUTED` 发布状态继续分开记账，也不能冒充第 4.6.5 节的
> v23 历史动态结果。
> 下述历史 production pins 与 v12 动态记录冻结在 IAM head `0037`、Profile head `0003`、Demand head `0010`、
> Trust head `0007`、Taxonomy head `0002`，即 IAM37/Demand10/Trust7。Trust7 是 metadata-only
> 精确依赖 repin；Trust1..6 SQL、Trust/Appeal API 与事件合同保持逐字冻结。其中 Trust6 包含 “my active
> assignments” 发现、`/v1/app/trust/cases/{case_id}` 的 triage 包装读取，以及
> `/v1/app/trust/assigned-holds/{hold_id}` 的 hold-release 专用读取。Trust0007 SQL、完整 manifest
> 与 combined SHA-256 分别为
> `16d383778cb794402c786f5cae8c32744af30627928d35fff9182a97128e1fc3`、
> `27a51c55bddfcb2a4f1bd16a3160abbb3a417425f14077f4886c3c41c22d5124`、
> `ab857f25969d17afe63886afe136cda10814e538517c54c180503b82f5785c1b`。这份冻结的历史动态验收是
> v12/Trust6，使用
> `secrets/e2e-ten-account-v12/`、bundle `internal-sandbox-bundle-iam36-demand9-trust6`、project
> `desire-supply-e2e-ten-account-v12`、tag `e2e-ten-account-v12-iam36-demand9-trust6` 与 state
> `/private/tmp/desire-ten-account-e2e-state-v12.json`。十个账号覆盖八个独立职责；两个
> Finance 账号共享 `FINANCE_OPERATOR`，两个 Trust 账号共享 `TRUST_OFFICER`。fresh
> migration、同一 migration 容器的下一轮 exact skip、唯一一次完整 journey 与两轮完整
> restart 均已 GREEN；不得把这些历史运行结果写成 Trust7 动态证据。
> journey 精确返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，两轮 restart 均精确返回
> `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`。migration/taxonomy/reconcile/verify/identity
> one-shot 的最终 JSON 日志条数精确保持 `2/1/1/1/1`，两轮 restart 没有重跑任何 one-shot。
> v9 的逻辑 backup 与 fresh isolated-volume
> restore 演练也已精确返回 `DATABASE_BACKUP_READY` 和 `DATABASE_RESTORE_VERIFIED`，恢复后的
> 五个 catalog 再次全量 exact skip；这项 backup/restore 历史证据仍只对应 Trust5，不能写成
> v12/Trust6 的恢复演练。v10 在唯一 journey 中失败并保全，v11 虽完成唯一 journey，但 restart
> 时错误沿 Compose 依赖链重跑 one-shot，restart 证据无效；两者都只作失败历史。当前已有的是合成
> HTTPS/API 与持久状态证据；完整十账号的桌面/移动浏览器视觉 QA 尚未完成，Demand Owner 取消需求与
> Trust Officer 完成历史的历史定向应用内浏览器验收已经完成。旧 `e2e-seven-account-v5`、
> `e2e-six-role-v1` 及更早结果均仅作历史追溯，不能作为当前验收。全程禁止
> 真人资料、真实合同、真实资金、真实权益决定、公网暴露和 OpenAI Sites 发布。

## 1. 先选择要运行的入口

| 目的 | 使用入口 | 当前结论 |
| --- | --- | --- |
| 直接在浏览器体验新制度与五类反例 | `demo/` | 可运行；无账号、无持久化、无外部副作用 |
| 检查七角色、服务端权限、25 个动作、幂等和 SQLite 重启恢复 | `platform/local_synthetic` | 可运行；HTTP API，不是当前 `/v1/app` 产品页面 |
| 按十账号/八职责测试核心工作台 | `compose.yaml` | 历史 v25 checkout 的 fresh、十账号、provider-only、隐私安全日志与 stop/resume/restart 本地合成证据已 GREEN；current-head v27 仅静态验证，尚无 v27 动态或生产执行；真实升级存量 preflight、backup/restore 动态演练与完整视觉 QA 未执行；当前版本绑定的 backup/restore 静态入口已签入 |
| 开发 Python/Web | `.devcontainer/` | 可运行；不会自动启动产品 API/Web |

第一次检查建议依次执行第 2、3 节，再执行第 4.1 节静态检查。若只想先看界面，完成
第 2 节即可。

## 2. 浏览器制度 Demo

### 2.1 前置检查

在仓库根目录执行：

```bash
node --version
npm --version
```

Node.js 必须为 `22.13.0` 或更高。本次复验使用 `v22.22.3`。

### 2.2 安装与自动验收

```bash
cd demo
npm ci
npm test
npm run lint
npm exec tsc -- --noEmit
```

首次 `npm ci` 需要访问 npm registry。通过标准：

- `npm test` 最终显示 `17 passed / 0 failed`；
- lint 与 TypeScript 检查退出码均为 `0`；
- 输出中没有 deploy、publish、真实身份、支付或通知调用。

### 2.3 启动

```bash
npm run dev
```

打开终端显示的地址；当前默认是 `http://localhost:3000/`。不要打开
`/__debug`。停止时按 `Ctrl-C`；Vinext/Cloudflare 本地插件可能打印
`Tunnel closed`，这是本地开发进程清理提示，不表示建立或关闭了公网发布。

### 2.4 首屏边界检查

页面加载后逐项确认：

- 顶部持续显示 `G0A · 完全合成 · G1 NO-GO · G2 NO-GO`；
- 页面明确说明不连接真实用户、资金、签字、文件、通知或外部 AI；
- 有且只有五个场景入口：`正常旅程`、`拒绝不惩罚`、`付款结果未知`、
  `独立申诉`、`数据退出`；
- 右侧或页面下方有“合成证据时间线”，且说明刷新会丢失；
- 页面没有登录、上传、真实支付、真实签署或发布入口。

任何一项不成立都应停止，不要把页面用于真人或真实业务。

### 2.5 正常旅程检查

选择 `正常旅程`，反复点击工作台中的主动作，依次确认：

1. 逐目的合成 Consent 被明确记录；
2. Demand v1 资金为 `UNKNOWN` 时匹配停止；
3. “演示资金核验”后变为 `SECURED`，页面仍说明这不代表真实托管或到账；
4. 陈澄（虚构）接受邀请后才可进入选择；
5. 需求方与创作者分别明示接受同一 `Agreement v1`；
6. 里程碑资金核验后才可开工；
7. 交付、合同验收与受益者成果确认分别呈现；
8. 付款经过 `REQUESTED → PROCESSING → UNKNOWN`；
9. `UNKNOWN` 时不能盲目重试，只能由独立合成对账收敛为 `PAID`；
10. 复盘只显示情境事实，不生成全局人格分。

每个动作后，时间线都应新增 actor、authority、对象版本、理由和 correlation。

### 2.6 四类反例检查

- `拒绝不惩罚`：模拟拒绝后，选择资格为不可选，未来资格仍为
  `ELIGIBLE`，且没有负面排序特征；尝试选择应返回制度拒绝。
- `付款结果未知`：重复发起按钮只演示规则拒绝；独立对账前不得出现成功结论。
- `独立申诉`：让原决定人复核应得到 `REVIEWER_NOT_INDEPENDENT`；改由沈岸
  （虚构）复核后才可产生补救。
- `数据退出`：只能预览合成副本和预演分项删除结果；页面应持续显示“未执行真实
  导出或删除”。

最后刷新页面，确认状态恢复为固定初始 fixture。

## 3. 本地七角色合成 API

这个入口验证服务端角色与持久化，不驱动当前 `web/` 首页。不要期待在浏览器打开
`127.0.0.1:8000` 得到产品页面。

### 3.1 准备 Python 环境

```bash
cd platform
uv --version
uv sync --locked --extra test
```

首次同步可能需要网络。依赖已缓存后，复跑可改为：

```bash
uv sync --offline --locked --extra test
```

### 3.2 跑关闭契约与真实 loopback HTTP 测试

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  uv run --offline --locked --extra test \
  python -m unittest discover -s tests/local_synthetic -v
```

通过标准是 `Ran 11 tests` 和 `OK`。若受限 shell 报监听
`127.0.0.1` 的 `Operation not permitted`，应在普通本机终端重跑；不要通过改成
`0.0.0.0` 绕过，服务会主动拒绝非 loopback 地址。

### 3.3 启动服务

```bash
mkdir -p .local
PYTHONPATH=src uv run --offline --locked --extra test \
  python -m desire_platform.local_synthetic \
  --database "$PWD/.local/local-synthetic.sqlite3" \
  --host 127.0.0.1 \
  --port 8000
```

必须看到三行等价信息：

```text
LOCAL_SYNTHETIC · G1 NO-GO · G2 NO-GO · no external side effects
Listening only on http://127.0.0.1:8000
Database: .../local-synthetic.sqlite3 (disposable synthetic state; never publish or back up)
```

若端口已被占用，先找出并停止你自己启动的旧进程；不要改成 LAN 地址。

### 3.4 健康与七角色检查

另开一个终端：

```bash
curl --fail --show-error http://127.0.0.1:8000/health/live
curl --fail --show-error http://127.0.0.1:8000/health/ready
curl --fail --show-error http://127.0.0.1:8000/v1/local/personas
```

前两条应分别返回：

```json
{"status":"LIVE","profile":"LOCAL_SYNTHETIC"}
{"status":"READY","profile":"LOCAL_SYNTHETIC"}
```

第三条必须精确包含七个 persona ID：

```text
creator-chen
demand-owner
acceptance-beneficiary
case-operator
payment-initiator
finance-reconciler
appeal-reviewer
```

不能自行注册第八个账号。

### 3.5 完成第一个角色动作

仍在仓库 `platform/` 目录，执行：

```bash
guide_origin=http://127.0.0.1:8000
guide_cookie=.local/guide-cookie.txt
guide_bootstrap=.local/guide-bootstrap.json

curl --fail --show-error \
  -c "$guide_cookie" \
  -H "Origin: $guide_origin" \
  -H 'Content-Type: application/json' \
  --data '{"persona_id":"creator-chen"}' \
  "$guide_origin/v1/local/session"

curl --fail --show-error \
  -b "$guide_cookie" \
  "$guide_origin/v1/local/bootstrap" \
  -o "$guide_bootstrap"

guide_csrf="$(python3 -c 'import json; print(json.load(open(".local/guide-bootstrap.json"))["csrf"])')"
guide_revision="$(python3 -c 'import json; print(json.load(open(".local/guide-bootstrap.json"))["revision"])')"
guide_key="$(python3 -c 'import uuid; print(uuid.uuid4())')"

curl --fail --show-error \
  -b "$guide_cookie" \
  -H "Origin: $guide_origin" \
  -H "X-CSRF-Token: $guide_csrf" \
  -H 'Content-Type: application/json' \
  --data "{\"operation\":\"accept_consent\",\"expected_revision\":$guide_revision,\"idempotency_key\":\"$guide_key\",\"input\":{\"decision\":\"ACCEPT\"}}" \
  "$guide_origin/v1/local/actions"
```

最后一条应返回 `receipt.status=COMPLETED`，revision 增加 1。再次读取 bootstrap：

```bash
curl --fail --show-error -b "$guide_cookie" \
  "$guide_origin/v1/local/bootstrap"
```

当前阶段应从 `J01` 前进到 `J02`，下一责任动作应为 `publish_profile`。

所有后续写请求都必须使用最新 bootstrap 的 `csrf` 与 `revision`，并使用新的 UUIDv4
幂等键。完整 25 动作的角色顺序见
[本地合成多角色平台 ADR](/architecture/local-synthetic-multi-role-platform.md#10-操作者最短检查序列)。

### 3.6 服务端拒绝检查

至少验证以下行为：

- 缺少 Cookie：`401 SESSION_REQUIRED`；
- 错误 Origin：`403 ORIGIN_NOT_ALLOWED`；
- stale revision：`412 REVISION_MISMATCH`；
- 在 body 中加入 `actor`、`authority` 或 `organization_id`：
  `400 FORBIDDEN_INPUT_FIELD`；
- `payment-initiator` 尝试对账或 `case-operator` 尝试处理相关申诉：服务端拒绝，
  revision 不变。

预期制度拒绝不是系统崩溃，不应通过直接改 SQLite 绕过。

### 3.7 重启持久化检查

1. 在服务终端按 `Ctrl-C`，应看到 `Stopping local synthetic server.`；
2. 使用第 3.3 节完全相同的数据库路径重启；
3. 再用原 cookie 读取 bootstrap；
4. 确认 revision、阶段和事件时间线仍在。

SQLite 文件权限应仅限当前用户。它只包含合成进度，不要备份、上传或发布。需要重新
开始时，先停止服务，再将精确文件移到你确认可丢弃的位置；不要对工作区目录执行递归
删除。

## 4. Docker：真实 API composition（v12 动态证据已到 Trust6）

### 4.1 前置与静态检查

回到仓库根目录：

```bash
docker --version
docker compose version
python3 -B scripts/verify_container_stack.py
python3 -B scripts/verify_current_head_v29.py
python3 -B -m unittest \
  tests.deployment.test_container_stack \
  tests.deployment.test_internal_sandbox_tls -v
python3 -B -m unittest tests.deployment.test_postgres_operations_v27 -v
```

静态验证必须输出 `{"status":"OK"}`；Compose/Caddy 与离线 TLS 契约应共 13 个测试
全部通过；current-head verifier 必须只输出
`{"status":"CURRENT_HEAD_V27_STATIC_VERIFIED"}`，当前 PostgreSQL backup/restore 资产的 v27 静态测试也必须全部通过。
当前 v27 operations 文件共有五项静态合同，因此预期为 5/5 GREEN；这些检查不调用 Docker，
不执行 migration 或 backup/restore。

静态门禁还会读取 base、development 与 PostgreSQL operations 的 resolved Compose，要求每个
service 的日志配置精确为 Docker `local` driver + `max-size=10m` + `max-file=3` +
`compress=true`；真实 OIDC overlay 的静态合同也要求 guard 使用同一配置。它只对以后新建的
容器生效，名义保留量约 30 MiB/容器。`stop` 与同容器恢复保留日志，container removal 会连同本机
日志删除；不要 recreate 冻结的历史栈来回填。本机轮转不等于 Audit、集中日志、告警、PITR、
backup/restore 或敏感数据擦除。

不要使用默认 Compose project、旧 runtime bundle 或共享数据库执行 `docker compose up`。
合成 OIDC、TLS/CA、双 hostname 和无环 Compose 拓扑已经接线；2026-08-19 的验收边界为：

1. [x] IAM head `0037`、Profile head `0003`、Demand head `0010`、Trust head `0007`、
   Taxonomy head `0002` 的 SQL、catalog/manifest pin 已原子冻结；Trust7 只更新 metadata dependency；
2. [x] Compose 静态合同固定三份 config、十一个在线数据库 credential 和二十四个
   key carrier，合计精确 35 secret；二十四个 carrier 覆盖二十二个用途；
3. [x] tag `e2e-ten-account-v12-iam36-demand9-trust6` 的 API/Web/Edge 镜像已在目标
   Docker 主机 fresh build，并由 `desire-supply-e2e-ten-account-v12` 证明 OIDC、TLS、
   API/Web health 和十账号 workspace 隔离；
4. [x] 完整旅程仅执行一次，通过同源 HTTPS BFF 返回
   `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`；两轮完整持久服务停启均返回
   `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`。旧 `SEVEN_ACCOUNT_*`/`SIX_ROLE_*` 结果只作
   历史证据，未用于勾选这两项。
5. [x] Trust1..6 冻结业务合同已将 Trust officer 工作台前移到 assignment discovery +
   目标对象精确读取：active case assignments、active appeal assignments、assigned case triage
   读取，以及 `/v1/app/trust/assigned-holds/{hold_id}` 的 hold-release 读取；
6. [x] Trust6 已在 fresh v12 project 完成 migration、同容器 exact replay、唯一 journey 与
   两轮 restart；两轮均保持 one-shot 日志条数 `2/1/1/1/1`。Trust6 backup/restore、浏览器
   视觉 QA、PITR 与告警仍未完成。

在普通 Docker 主机或 CI 上，可用下面的一次性门禁生成第 1 项证据。它不使用
`compose.yaml` 或项目数据卷，结束时会清理临时 PostgreSQL 容器：

```bash
cd platform
sh scripts/test_iam_session_security_pg18.sh
```

通过标准是 `13 passed`。这是冻结的 IAM0024 session-security 回归切片，不替代
IAM0027 account-workbench、IAM0028/0029 policy-consent 修复和 Demand0005 review-queue 的
独立 PG18 证据。出现任何失败、
跳过、容器残留或非零退出码，都不能继续完整 Docker 初始化。已有专用、可销毁的
PostgreSQL 18 时，可改用：

```bash
DESIRE_IAM_TEST_POSTGRES_DSN='postgresql://...' \
DESIRE_IAM_TEST_POSTGRES_EPHEMERAL=1 \
  sh scripts/test_iam_session_security_pg18.sh
```

这个模式会验证 PostgreSQL 主版本为 18，并要求显式声明实例可销毁；不要指向共享、生产
或含有需要保留数据的数据库。

下面第 4.2–4.6 节记录 IAM36/Profile3/Demand9/Trust6/Taxonomy2 的已执行 v12 动态验收顺序。
v12 已完成且所有 state/result、one-shot 容器与日志必须保全；这些合成证据不是跳过前置门禁、
引入真人或真实业务数据的授权。

### 4.2 创建输入与 runtime bundle

Docker 入口不再使用旧 `session_hmac_key` 或让 API 读取 superuser。现在需要：

- 一份仅 deployment job 使用的 PostgreSQL superuser password；
- taxonomy workload credential 与 exact 32-byte receipt HMAC key；
- 合成 OIDC client secret 与离线生成的双 SAN TLS fixture；
- 十个固定虚构账号的二十个 subject/email source 文件；
- bundle generator 产出的三份配置、十一个在线 DB credential 和二十四个 key carrier。

精确创建命令、固定虚构值、权限与 OIDC 参数见
[INTERNAL_SANDBOX 容器部署](/operations/container-deployment.md#3-v12-输入bundle-与-compose-绑定)。
bundle 命令成功时必须报告 `database_credential_count=11`、`key_count=24`、
`secret_count=35`，且 `output_dir` 必须精确等于本轮绝对 bundle 路径；输出目录存在时必须失败，
不得覆盖。

目标实例使用 `secrets/e2e-ten-account-v12/` 中的四份 deployment secret、二十份 identity
source 和 TLS；目标 35-secret bundle 位于
`internal-sandbox-bundle-iam36-demand9-trust6/`。Demand idempotency 与 payload 两个用途都按
active `2026-01` 在前、`VERIFY_ONLY` retained `2025-12` 在后的精确顺序各挂两个
carrier；API readiness 在请求前要求 runtime 与数据库 policy 元组完全一致。数据库
必须为 IAM36/Profile3/Demand9/Trust6/Taxonomy2。旧 `secrets/e2e-ten-account-v9/`、失败的
v10/v11、`secrets/e2e-seven-account-v5/`、`secrets/e2e-six-role-v1/` 及更早树只作历史证据，不得
混入当前 project。不得覆盖 bundle、混合材料或删除任何 volume。`compose.env`
必须使用绝对路径并固定相同 image tag。然后在仓库根终端定义：

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

后续本节所有 Compose 操作都使用 `compose_e2e`；新开终端后先重新定义函数。

### 4.3 构建和有序初始化

以下是 v12 已执行并保全容器证据的精确顺序，仅供审计，不是复跑指令。不要在 v12 原地重建、
删除、替换或重新启动任何 one-shot 容器，也不得重跑 journey 或 restart verifier；需要新的
验收只能创建新的版本化 project、输入树、bundle、tag 和 state 路径。

```bash
compose_e2e build api web edge

compose_e2e up -d --wait --wait-timeout 120 synthetic-oidc edge
compose_e2e up -d --wait --wait-timeout 120 db
compose_e2e up -d --no-deps migrate
docker wait desire-supply-e2e-ten-account-v12-migrate-1
compose_e2e logs --no-log-prefix migrate

# 第二次 migration 只直接启动同一个固定容器，避免 Compose 遍历依赖；此动作已消费。
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
```

五类 one-shot 日志必须依次包含 `SCHEMA_READY`、
`INTERNAL_SANDBOX_TAXONOMY_SEED_READY`、两次 `ONLINE_CREDENTIALS_READY`，以及
`IDENTITY_BOOTSTRAP_ORCHESTRATION_READY`/`VERIFIED`；两次 credential 日志的在线角色数量都
必须为 11。identity manifest 的动态 digest 只在同一 Python 进程内交接，digest-only 文件
只写到容器 tmpfs。

v12 fresh migration 的第一轮 applied 精确为 IAM `0..36`、Profile `1..3`、Demand `1..9`、
Trust `1..6`、Taxonomy `1..2`，五个 skipped 集合均为空；第二轮 applied 五项均为空，
skipped 精确为同一组版本。taxonomy fresh 结果为 `replayed=false`，identity 为
`APPLIED`/`VERIFIED`。最终 migration/taxonomy/reconcile/verify/identity JSON 日志条数精确为
`2/1/1/1/1`。这些结果已消费，不应再启动 v12 的任何 one-shot 容器；不能使用 `run --rm`，
更不能删除 container 或 volume。任何未来 credential 轮换必须使用新的版本化 project，不能
在 v12 原地执行。

### 4.4 启动和检查未发布 API

```bash
compose_e2e ps -a
compose_e2e exec -T api python -c \
  "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2).read().decode())"
```

API 现在是真实 composition；满足全部数据库、schema、seed、artifact、secret 与 OIDC
preflight 时应返回 HTTP 200 `status=READY`，同时仍明确
`INTERNAL_SANDBOX / G1 NO-GO / G2 NO-GO`。配置缺失、OIDC 不可达或任一 readiness
失败时，API 在监听前以 78 退出或在运行中返回 503，不能回退 placeholder/Memory/no-op。

API 没有 host port、没有 superuser secret；除 deployment config pointer 外只设置标准
`SSL_CERT_FILE` 指向只读 root CA。只有 edge 声明 `127.0.0.1:443`。API 经 `app`
internal network 上的 `identity.example.test` edge alias 访问 HTTPS OIDC，不加入一般
egress；IdP 只加入独立 `oidc-backend` internal network。

已启动的 v12 可从宿主机只读检查 edge：

```bash
curl --fail --show-error \
  --cacert secrets/e2e-ten-account-v12/internal-sandbox-tls/root-ca.pem \
  --resolve pilot.example.test:443:127.0.0.1 \
  https://pilot.example.test/
```

### 4.5 十账号浏览器、账号管理与职责隔离

当前固定账号为：

- `access_admin_01`、`appeal_reviewer_01`、`creator_01`、`demand_owner_01`；
- `operations_reviewer_01`、`finance_operator_01`、`finance_operator_02`；
- `org_admin_01`、`trust_officer_01`、`trust_officer_02`。

十个账号覆盖 `ACCESS_ADMIN`、`APPEAL_REVIEWER`、`CREATOR`、`DEMAND_OWNER`、
`OPERATIONS_REVIEWER`、`FINANCE_OPERATOR`、`ORG_ADMIN`、`TRUST_OFFICER` 八个职责；两个
Finance 账号共享 Finance 职责，两个 Trust 账号共享 Trust 职责。每个账号必须使用独立
cookie/storage，会话只能发现被授予的 workspace。

v12 自动旅程已证明十账号 workspace 隔离、账号/组织管理、核心 Demand/Finance 流程以及
Trust/Appeal 闭环；但本机 URL 安全策略下尚未完成应用内浏览器视觉 QA，不能把 HTTP、runner
或健康检查写成桌面/移动视觉验收。下列 v5 七账号步骤保留为历史行为说明，不是当前账号清单：

历史 v5 使用 `access_admin_01`、`creator_01`、`demand_owner_01`、`operations_reviewer_01`、
`finance_operator_01`、`finance_operator_02`、`org_admin_01` 登录。七个账号代表六个独立
职责；它已完成 HTTPS runner，但未完成视觉 QA。旧六账号及更早结果也只作历史证据。

在管理员 profile 中选择平台职责工作区，按顺序检查：

1. 左栏“账号管理”精确列出十个合成账号；另外九个账号均看不到入口；
2. 管理员自己的可见操作全部禁用，详情不包含邮箱、OIDC subject、digest 或组织授权；
3. 对已登录的 `creator_01` 用 `ACCESS_REVIEW` 执行“暂停账号”，确认版本递增、会话归零，
   Creator 旧会话立即失效；
4. 执行“恢复账号”，确认状态恢复正常但旧 cookie 不复活，Creator 必须重新 OIDC 登录；
5. Creator 重新登录后，用 `SESSION_HYGIENE` 执行“撤销全部会话”，确认账号仍为 ACTIVE、
   会话归零且可重新登录；
6. 两个管理员标签页用同一旧 ETag 操作时，后提交者必须得到
   `PRECONDITION_FAILED`；网络/5xx 导致结果未知时只能“原样重试”同一请求。

随后用任一仍为 ACTIVE 的固定账号打开“我的会话”：列表必须把当前 bootstrap Session 标为
“当前”，只显示安全设备标签、时间、状态与短 ID，并可手动刷新和按服务端游标加载更多。当前
ACTIVE 会话提供“退出此当前会话”；其他 ACTIVE 会话提供两步确认的“撤销此会话”，成功后
fresh GET 必须同时证明目标已终态且当前 bootstrap Session 仍为 ACTIVE。网络或 5xx 导致结果
未知时，只能用绑定当前账号、bootstrap Session、目标、CSRF 与原幂等键的恢复对象原样重试，
不得改换目标或扩大为全部撤销；终态会话不得出现操作按钮。读取页面属于 IAM37，其他会话撤销
属于 IAM38；两者都不属于已保全的 v12 runner 动态证据，实际部署验收必须另行记录。

这些字段闭合、请求检查与失败判据已由 v12 runner 记录；接着在 `org_admin_01` 的
ORGANIZATION workspace 检查：

1. “组织成员与邀请”只对 ORG_ADMIN 可见；邀请和成员列表来自 IAM，并只显示脱敏、无 token
   的管理 DTO；
2. 向 `sandbox-creator-01@example.test` 发出 `DEMAND_OWNER` 邀请并原样重放。两次必须返回同一
   invitation/ETag；capability token 只能放在 `/join#access_invitation_token=...` fragment，
   不得进入 query、Referer、日志或 state 文件；
3. `creator_01` 在自己的隔离 profile 打开 join URL。页面取出 token 后必须立即清除 fragment，
   完成 synthetic step-up、政策确认和接受后，才新增 ORGANIZATION `DEMAND_OWNER` workspace；
4. ORG_ADMIN 刷新成员列表，使用 fresh ETag 依次暂停、恢复、撤销该 membership，每个命令都
   原样重放；Creator 的组织 workspace 必须消失、恢复、再次消失，PERSONAL workspace 保留；
5. 向 `sandbox-finance-operator-01@example.test` 发出第二份邀请但不接受，随后撤销。自我管理、
   最后一名 ACTIVE ORG_ADMIN、stale ETag 与跨组织请求必须失败关闭且零写入；
6. 完整重启后读回：首份 invitation 为 `ACCEPTED`、对应 membership 为 `REVOKED`、第二份
   invitation 为 `REVOKED`。

这组检查只允许十个固定合成账号，不改变 `G1 NO-GO / G2 NO-GO`。

### 4.6 十账号/八职责核心业务闭环与已保全证据

按以下顺序操作；只使用页面从 `/v1/app/configuration` 自动取得的当前 taxonomy，不手填或
复制测试 UUID：

1. `creator_01` 首次登录时逐份确认必需政策，创建 Profile，完成九个分区并发布；状态应为
   `ACTIVE`；
2. `demand_owner_01` 完成自己的政策确认，创建 Demand，完成十三区并提交；状态应为
   `SUBMITTED`；
3. `operations_reviewer_01` 从最小审核队列领取该 Demand，打开 fresh detail，以顶层字段路径
   `/scope` 记录 `SCOPE_UNCLEAR`；状态应为 `NEEDS_CHANGES`，第一次 assignment 关闭；
4. Owner 补充范围说明并重新提交；Reviewer 必须重新从队列领取，第二个 assignment ID 必须
   与第一次不同；
5. Reviewer 使用闭合 budget/risk/evidence codes 完成验证；最终状态应为 `VERIFIED`，该 Demand
   不再出现在审核队列；
6. `finance_operator_01` 领取 VERIFIED Demand；详情必须把审查绑定的不可变 DemandVersion、
   content SHA-256 和计划合成预算，与实际资金 `0`、provider `NONE`、PaymentOperation `NONE`
   明确分开显示，而不是只给两个哈希；核对后显式勾选四项零资金合成声明并完成第一份确认；
7. `finance_operator_02` 以最新 review ETag 加入并完成第二份独立确认；Demand 变为 `FUNDED`，
   全程金额为零且法律效果为 `NO_REAL_FUNDS_OR_PAYMENT`；
8. 完成第 4.5 节 ORG_ADMIN 邀请/接受/成员生命周期以及 Trust/Appeal 独立复核闭环，不删除
   container 或 volume，只用 `up -d --no-deps --no-recreate --wait` 按
   `db` → `synthetic-oidc` → `edge` → `api` → `web` 恢复五个已停止的持久服务；禁止
   `start api`/`start web` 沿依赖链重跑 one-shot。重新登录后读取 Profile/Demand，必须仍为
   `ACTIVE`/`FUNDED`，账号列表仍精确十项，并读回管理与 Trust/Appeal 终态。

v12 project 的唯一一次 journey 已使用
`/private/tmp/desire-ten-account-e2e-state-v12.json` 并精确返回
`TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`；随后两次完整停止/启动五个持久服务的复验均精确返回
`TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`。两轮恢复均只用
`up -d --no-deps --no-recreate --wait --wait-timeout 120`，one-shot 日志条数始终保持
`2/1/1/1/1`。state 已存在且唯一 journey 与两份 restart verifier 均已消费，禁止在 v12
再次执行 `journey`、覆盖 state 或用新 state 冒充同一堆栈的首次旅程。这里的 MFA 是 synthetic
IdP 明确标记的模拟 MFA，不代表真人 MFA 或生产 step-up 证明。

历史 v9/Trust5 的 journey、两轮 restart 与 backup/restore 均 GREEN；v10 的唯一 journey 失败，
v11 的唯一 journey GREEN 但 restart 因依赖链重跑 one-shot 而无效。三者都已保全，不能替代
v12 状态。更早 v5 的 `SEVEN_ACCOUNT_ORG_ADMIN_*` 与 `SIX_ROLE_*` 同样只作追溯。

### 4.6.1 当时 checkout 本地试用管理器动态验收（2026-08-25）

2026-08-25 当时 checkout 已在全新、隔离的本地试用栈生成以下去标识动态证据；项目坐标、网络坐标、临时路径和
任何认证材料均不写入本文：

1. fresh PostgreSQL migration 到达 IAM `0040` 与 Trust `0013`，五个持久服务通过健康门禁，
   管理器状态为 `HEALTHY`；
2. 十个 bootstrap 合成角色账号的完整核心旅程 GREEN；第十一个 provider-only 身份不在 bootstrap
   角色或权限中；
3. 该 provider-only 身份先以 pending 状态出现，接受邀请前没有角色或工作区。它完成精确邀请绑定的
   enrollment 与接受后，只取得目标组织的 `DEMAND_OWNER`；管理入口对它保持 `404`；
4. 这个邀请创建的 Demand Owner 完成 Demand create、幂等 replay、cancel 和只读完成历史读取，
   未取得其他组织角色、user role 或 platform duty；
5. 数据库去标识聚合为 11 个 active user、0 个 pending user、11 个 external identity；目标身份仅有
   一条目标组织 `DEMAND_OWNER`，user role 与 platform duty 都为零；
6. 管理器完成 `STOPPED → resume → HEALTHY`，restart verifier GREEN；最终再次停止为 `STOPPED`，
   没有重建容器、重跑 one-shot 或删除资源，PostgreSQL volume 与其余验收资源均保留。

这是 2026-08-25 当时 checkout 的本地 HTTPS/API、数据库聚合与持久性验收，不是 current-head v19
或 v20 的发布执行记录，不改变其 `STATIC / NOT EXECUTED` 声明，也不构成生产授权或完整桌面/移动浏览器视觉 QA。

### 4.6.2 历史 checkout IAM41/Trust14 本地动态验收（2026-08-26）

2026-08-26 当时 checkout 在另一套全新、隔离且最终保留的本地试用栈完成以下去标识动态证据；
项目坐标、网络坐标、临时路径、对象 ID 与任何认证材料均不写入本文：

1. fresh PostgreSQL migration 精确到达 IAM `0041`、Profile `0003`、Demand `0011`、
   Trust `0014` 与 Taxonomy `0002`；五个 one-shot deployment service 和五个持久服务全部通过门禁，
   管理器状态为 `HEALTHY`；
2. 十个 bootstrap 合成账号的完整旅程返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`。其中 ACTIVE
   Creator 再接受目标组织 `DEMAND_OWNER` 时，接受前的 `CREATOR` 与已满足策略要求被完整保留，
   只新增一条目标组织 membership 与对应已满足要求，User 版本和 tag 精确 `N → N+1`，接受响应
   `me` 与随后 `/v1/me` 完全相等，且 `/v1/me` HTTP ETag 等于 User tag；
3. 独立 provider-only 身份从 pending、无角色、无 membership、无 workspace 开始，接受后只取得
   目标组织 `DEMAND_OWNER`，并完成 Demand create、exact replay、cancel 与只读历史，结果返回
   `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`；
4. 管理器完成 `HEALTHY → STOPPED → resume → HEALTHY`，同一只读 state 的 restart verifier 返回
   `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`；恢复只启动五个持久容器，没有重跑 migration、seed、
   credential 或 identity bootstrap one-shot；
5. 最终再次停止为 `STOPPED`，没有执行 `down`、删除、清理或覆盖；PostgreSQL volume、容器、网络、
   镜像、失败现场与结果文件均保留。首次隔离尝试曾由真实 PG18 动态发现 IAM41 缺少 runner
   artifact assertion 映射，事务在 IAM40 后关闭失败并保全；补齐 head `41` 映射和回归后，使用
   全新坐标的第二次 fresh 尝试完成上述 GREEN 结果。

这项历史证据关闭了当时 IAM41 canonical Me、ACTIVE User 版本失效、PENDING enrollment 和容器
持久性本地门禁；它不把 current-head v20 或 v21 的静态声明改写为发布执行，不构成生产授权，
也不替代 IAM42/Trust15 动态验收、桌面/移动视觉 QA、逻辑 backup/isolated restore、加密离机备份、
PITR、告警或真实 OIDC 验收。

### 4.6.3 历史：v21 IAM42/Demand11/Trust15 本地动态证据（2026-08-26）

当时 checkout 已在全新、隔离、版本化坐标上生成以下去标识结果；本文不登记项目/网络坐标、
对象 ID、认证材料或公开名称原值：

1. fresh 空数据卷精确应用 IAM `0..42`、Profile `1..3`、Demand `1..11`、Trust `1..15`、
   Taxonomy `1..2`；五个 one-shot 均以 0 退出，五个持久服务达到 `HEALTHY`；
2. 十账号/八职责完整旅程返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`。ORG_ADMIN 在最近 MFA、CSRF、
   强 `If-Match` 与 `Idempotency-Key` 下更新组织公开名称并 exact replay；同一未接受邀请的 inspect
   通过 live join 立即显示新名称，Invitation ID/version/ETag/token 与 policy binding 不变；
3. provider-only 身份在接受前无角色、membership、workspace 或管理 surface；接受后只得到目标组织
   `DEMAND_OWNER`，并完成 Demand create/replay/cancel/history，返回
   `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`；
4. 管理器完成 `HEALTHY → STOPPED → resume → HEALTHY → STOPPED`；resume 只启动收据绑定的五个
   既有持久容器，没有重跑 one-shot。restart verifier 返回
   `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`，并从数据库重新读取到更正后的名称；所有容器、网络、
   volume、state、日志和失败现场均保留；
5. 首次隔离运行在公开名称响应校验处 fail-closed，事务未提交。根因是生产 IAM validator 未登记
   OpenAPI 已审查的 `OrganizationSummaryDto`；增加该唯一白名单与正/负回归后，另一套全新坐标完成
   上述 GREEN 结果。修复后完整非 PG18 套件 1,514 项、真实 PG18 集成套件 364 项均全绿；
6. fresh 数据卷在 IAM42 前没有存量组织，故本次只证明零存量升级路径。当前 migration composition
   已在 provisioning advisory lock 后、任何 provisioning/catalog 写入前自动运行固定 timeout 的
   `REPEATABLE READ READ ONLY` 全量 preflight：NFC、精确 trim、1..160 Unicode code point、禁
   `Cc`/`Cf`，且只输出聚合计数。preflight 与旧 API writer 不在同一事务，不能声明在线升级原子性；
   真实服务器必须先停止并排空旧 API/worker，确认无 live writer，再在同一静默窗口扫描和迁移。
   异常先受控修复并重扫，禁止自动 normalize、禁用 CHECK、修改 migration bytes、手改 ledger 或
   跳过 IAM42；IAM42 CHECK 仍是最终竞态门禁，但不是省略 writer quiescence 的理由；
7. migration runner exact replay 已由真实 PG18 集成测试证明，但本次一次性 manager 未重跑 migration
   one-shot。逻辑 backup/isolated restore、桌面/移动视觉 QA、PITR、告警、加密离机备份与真实 OIDC
   仍未完成，不能据此授权生产。

### 4.6.4 历史冻结：v22 IAM42/Demand12/Trust16 本地动态证据（2026-08-26）

当时的 runtime/source 代码（完成后只新增本节去标识记录）已在全新、隔离、版本化坐标上生成以下结果；
本文不登记 root、project、tag、CIDR、对象 ID、认证材料或公开名称原值：

1. fresh 空数据卷精确应用 IAM `0..42`、Profile `1..3`、Demand `1..12`、Trust `1..16` 与
   Taxonomy `1..2`；migration、taxonomy seed、credential reconcile/verify、identity bootstrap
   五个 one-shot 全部以 0 退出，五个持久服务进入 `HEALTHY`；
2. 十账号/八职责旅程返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`。临时为一个
   `FINANCE_OPERATOR` 配置 `TRUST_OFFICER` duty 后可发现对应工作区、原 Finance 操作仍可用；撤销后
   角色集合精确恢复。两名 Finance 确认者都能从本人完成历史重新发现 `SECURED` review，terminal
   finding 只对提交者可见，分页与 active-queue 缺席边界均通过；
3. ORG_ADMIN 公开名称更正、exact replay 与未接受邀请 live join 通过；独立 provider-only 身份从
   pending 零权限开始，接受后只取得目标组织 `DEMAND_OWNER`，完成 Demand
   create/replay/cancel/completed-history，并返回 `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`；
4. 管理器完整经过 `HEALTHY → STOPPED → resume → HEALTHY → STOPPED`；resume 只启动五个收据绑定
   的既有持久容器，未重跑 one-shot。restart verifier 返回
   `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`，并重新读取 Finance 完成历史、Trust/Appeal 终态、
   账号投影和更正后的组织公开名称；所有容器、网络、卷、镜像、state/result 与失败现场保留；
5. 两个较早的全新尝试均 fail-closed 并只停止保留：第一次把 evidence 写进封存 input root，动态
   暴露 manager 正确拒绝输入树漂移；runner 现会在任何登录/业务动作前拒绝该路径及祖先 symlink
   绕回。第二次在 restart 历史查询前暴露封闭 failure-stage 枚举漏登；补齐精确 stage 和回归后，
   第三套全新坐标完成上述 GREEN，不复用任何失败坐标；
6. 完整平台 pytest 在 PostgreSQL 18 上 `1,898` 项全绿；Web typecheck、lint 与 `190` 项契约测试、
   MVP `134` 项、Demo build/lint/typecheck 与 `17` 项测试也全绿。部署契约在最终文档后另行全量复验；
7. 本次仍是 fresh 零存量路径，不替代真实服务器 IAM42 `public_name` 存量 preflight。上线必须先停止
   并排空旧 API/worker，确认无 live writer，再在同一静默窗口执行只读扫描和 migration。逻辑
   backup/isolated restore、完整桌面/移动视觉 QA、PITR、告警、加密离机备份与真实 OIDC 仍未完成。

### 4.6.5 历史：v23 IAM42/Demand12/Trust17 本地动态证据（2026-08-26）

当时的 runtime/source 已在一套全新、隔离的本地合成 fresh-volume 栈完成以下去标识验收；最终
`STOPPED` 后只追加去标识文档记录，应用、Docker、migration 与 runtime source 未再变化。本节不登记
root、project、tag、CIDR、对象 ID 或认证 ID：

1. fresh migration 到达 IAM `0042`、Profile `0003`、Demand `0012`、Trust `0017`、Taxonomy
   `0002`；管理器从 `PREPARED` 进入 `HEALTHY`，五个 one-shot 成功且五个持久服务健康；
2. 十账号/八职责旅程返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，独立 provider-only invited
   Demand Owner 旅程返回 `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`；
3. 管理器经过 `STOPPED -> resume -> HEALTHY`，restart verifier 返回
   `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`；摘要同时证明
   `trust_terminal_history_discoverable=true` 与 `terminal_history_actor_scoped=true`，即完成案件可由
   本人重新发现且同岗 actor 隔离保持；
4. 最终状态回到 `STOPPED`。精确保留十个容器、四个网络、一个 PostgreSQL volume、三个应用镜像，
   全部容器 `RestartCount=0`；四份互异 evidence JSON 均为 `0600` regular file；
5. 全程未执行 `down`、删除、remove 或 cleanup。所有资源和证据继续保留，不复用或覆盖。

这只是合成本地 fresh-volume 动态证据，不是 production migration、production deployment、真实存量
升级、backup/restore、完整视觉 QA 或发布授权。current-head v23 页面继续保持
`STATIC VERIFIED / NOT PRODUCTION EXECUTED`。

### 4.6.6 历史冻结：v24 IAM42/Demand12/Trust18 本地动态证据（2026-08-26）

当时的 v24 runtime/source 已在另一套全新、隔离的本地合成 fresh-volume 栈完成以下去标识验收；最终
`STOPPED` 后只追加去标识文档记录。本节不登记 root、project、image tag、CIDR、对象 ID 或认证 ID：

1. fresh migration 到达 IAM `0042`、Profile `0003`、Demand `0012`、Trust `0018`、Taxonomy
   `0002`；管理器从 `PREPARED` 进入 `HEALTHY`，五个 one-shot 成功且五个持久服务健康；
2. 十账号/八职责旅程返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，独立 provider-only invited Demand
   Owner 旅程返回 `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`；
3. Appeal Reviewer 本人完成复核的 history list、终态 detail 与 completed task 均可重新发现；错误角色
   list/detail 返回 `404`，额外 query 返回 `400 INVALID_REQUEST`。临时获得同岗 duty 的第二名 reviewer
   只能看到空的本人 history，读取第一名 reviewer 的终态 detail 返回 `404`，随后 duty 已恢复原状；
4. 管理器经过 `STOPPED -> resume -> HEALTHY`，restart verifier 返回
   `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`，并从保留数据库重新发现 Trust 与 Appeal 终态事实；
5. 最终状态回到 `STOPPED`。十个启动收据绑定的容器、四个网络、PostgreSQL volume、应用镜像与四份
   私有 evidence JSON 均保留；全程未执行 `down`、delete、remove、`--rm` 或 prune；
6. Platform `1929` 项、Web `200` 项（包含 production build）与 deployment `536` 项全绿；v24 静态
   verifier 与 103 页文档 verifier 也通过；
7. 应用内 Browser 的隔离 `localhost` 无法桥接到宿主机 Docker loopback。临时 hosts 映射已逐字恢复，
   未安装 CA trust，也未绕过证书警告；因此完整桌面/移动视觉 QA 继续保持未完成。

这只是合成本地 fresh-volume 动态证据，不是 production migration、production deployment、真实存量
升级、backup/restore、完整视觉 QA 或发布授权。冻结的 current-head v24 页面继续保持原字节与
`STATIC VERIFIED / NOT PRODUCTION EXECUTED` 声明；它不是 v25 动态证据。冻结的 current-head v25
同样只是 `STATIC VERIFIED / NOT PRODUCTION EXECUTED`，也不是 v26 动态证据。

### 4.6.7 历史：v25 checkout 本地合成动态验收（2026-08-26）

绑定 fresh manager source receipt 的 IAM42/Profile3/Demand12/Trust18/Taxonomy2 runtime/source 已在
全新隔离坐标完成以下去标识验收；最终 `STOPPED` 后只新增文档记录。本节不登记 root、project、
image tag、CIDR、对象 ID 或认证 ID：

1. fresh PostgreSQL volume 上五个 one-shot 全部成功，五个持久服务达到 `HEALTHY`，管理器从
   `PREPARED` 进入 `HEALTHY`；
2. 十账号/八职责旅程返回 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，provider-only invited Demand
   Owner 旅程返回 `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`；
3. receipt-bound Web 包含编辑器在写入进行中/结果未知时的整组控件锁、Finance continue/wait task 的
   fresh exact 只读详情入口，以及邀请到期时间的本地墙钟/UTC 严格转换。production build 与 Web
   `206` 项、deployment `549` 项、v25 静态 verifier 均 GREEN；未改动 Platform source 的 `1935` 项
   GREEN 基线继续有效；
4. 抽样查看的近期 live API boundary entries 只出现闭合的 `HTTP_BOUNDARY_OBSERVATION_V1` 字段；该样本
   不含 raw target/query/header/body、actor/object/trace ID 或异常文本。manager 同时复核所有新容器的 Docker logging 精确为
   `local / 10m / 3 / compress=true`；
5. `STOPPED -> resume -> HEALTHY` 后，restart verifier 返回
   `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`，从保留数据库重新发现 Finance、Trust、Appeal、Organization、
   account、Profile 与 Demand 终态；
6. 最终再次 `STOPPED`。十个 receipt-bound 容器、四个网络、PostgreSQL volume、应用镜像和位于
   `0700` 目录内的四份 `0600` evidence JSON 均保留；没有执行 `down`、delete、remove、`--rm` 或 prune；
7. 应用内 Browser 无法到达宿主机 loopback 的合成 HTTPS 入口，并返回连接关闭/站点不可达。未安装 CA
   trust、未绕过证书警告，也未修改 hosts 或系统信任配置，因此完整桌面/移动视觉 QA 仍未完成。

这项结果只证明受检 checkout 的本地合成 fresh-volume composition、角色闭环、低基数日志和保留式重启。
它不是 production migration/deployment、真实存量升级、backup/restore、真实 OIDC 或发布授权；
冻结的 current-head v25 静态页面继续保持 `STATIC VERIFIED / NOT PRODUCTION EXECUTED` 与
`production_authorized=false`；本节不是 current-head v26 动态证据。

### 4.7 停止且保留数据库

```bash
compose_e2e stop web
compose_e2e stop api
compose_e2e stop edge
compose_e2e stop synthetic-oidc
compose_e2e stop db
```

只停止这五个持久服务；保留所有已退出 one-shot 容器、network、`postgres-data` volume、
state 和日志。对当前或失败 project 都不得执行 `down`、`down -v`、`down --volumes`、
`rm` 或 `run --rm`。

以下 v13 标题与 `CURRENT_HEAD_V13_*` marker 是历史 verifier 的冻结标签；整段只作审计证据，
不再是 current pointer，也不得据此消费旧坐标。

### 4.7.1 当前头部 v13 fresh、replay、journey 与 restart（一次性）

下面是 IAM37/Profile3/Demand10/Trust7/Taxonomy2 的历史 current-head 验收协议。它固定 project、tag、
输入根、bundle、deployment/release、四个 CIDR 和本地证据路径。远端 manifest 门禁 GREEN 且首次
创建开始后，任一命令非零、任一结果形状不符或 operator harness 无效，都会永久锁定全部 v13
坐标，不得重试、停止、清理、补跑或用另一 state/result 路径冒充 fresh。开始前必须在同一个
shell 完成所有只读 namespace、镜像、
端口、Docker CIDR、LAN 与 VPN 路由检查。四个候选 `/24` 只适用于本轮受检宿主机，不是通用
默认值。所有本地只读占用检查 GREEN 后、任何 v13 input/evidence 目录创建或 build 前，必须
精确执行一次 Docker Hub manifest-only 门禁；同一次 invocation 内五个 production ref 的三轮
HEAD（共 15 次）必须全部 GREEN。任一次 token/HEAD、状态码或 digest 检查失败都会使整次观察
作废：程序内部不得重试，也不得拼接不同 invocation 的成功结果；若再次检查，必须从第一轮开始
一组全新的完整 invocation。在某一组完整 GREEN 前不得创建或消费这组 v13 坐标。该门禁只读
manifest metadata，不拉取镜像层，也不创建或启动容器：

```bash
# BEGIN CURRENT_HEAD_V13_FRESH_RUNBOOK
set -eu
set -o pipefail
test "$(pwd -P)" = "/Users/shiyaozhang/Developer/desire-supply"
test -z "${COMPOSE_PROJECT_NAME+x}"
test -z "${COMPOSE_COMPATIBILITY+x}"
test -z "${DESIRE_DB_PASSWORD_FILE+x}"
test -z "${DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE+x}"
test -z "${DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE+x}"
test -z "${DESIRE_IDENTITY_SOURCE_DIR+x}"
test -z "${DESIRE_INTERNAL_SANDBOX_TLS_DIR+x}"
test -z "${DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR+x}"
export DESIRE_E2E_PROJECT="desire-supply-e2e-ten-account-v13"
export DESIRE_IMAGE_TAG="e2e-ten-account-v13-iam37-demand10-trust7"
export DESIRE_E2E_INPUT_ROOT="/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13"
export DESIRE_E2E_BUNDLE_NAME="internal-sandbox-bundle-iam37-demand10-trust7"
export DESIRE_E2E_BUNDLE_DIR="$DESIRE_E2E_INPUT_ROOT/$DESIRE_E2E_BUNDLE_NAME"
export DESIRE_E2E_DEPLOYMENT_ID="sandbox-e2e-ten-account-v13"
export DESIRE_E2E_RELEASE_ID="release-e2e-ten-account-v13-iam37-demand10-trust7"
export DESIRE_E2E_INGRESS_SUBNET="172.16.227.0/24"
export DESIRE_E2E_OIDC_SUBNET="172.16.228.0/24"
export DESIRE_E2E_APP_SUBNET="172.16.229.0/24"
export DESIRE_E2E_DATA_SUBNET="172.16.231.0/24"
export DESIRE_E2E_EVIDENCE_DIR="$DESIRE_E2E_INPUT_ROOT/e2e-evidence"
export DESIRE_E2E_STATE="$DESIRE_E2E_EVIDENCE_DIR/state.json"
export DESIRE_E2E_JOURNEY_RESULT="$DESIRE_E2E_EVIDENCE_DIR/journey-result.json"
export DESIRE_E2E_RESTART_1_RESULT="$DESIRE_E2E_EVIDENCE_DIR/restart-1-result.json"
export DESIRE_E2E_RESTART_2_RESULT="$DESIRE_E2E_EVIDENCE_DIR/restart-2-result.json"

test "$DESIRE_E2E_PROJECT" = "desire-supply-e2e-ten-account-v13"
test "$DESIRE_IMAGE_TAG" = "e2e-ten-account-v13-iam37-demand10-trust7"
test "$DESIRE_E2E_INPUT_ROOT" = "/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13"
test "$DESIRE_E2E_BUNDLE_DIR" = "/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/internal-sandbox-bundle-iam37-demand10-trust7"
test "$DESIRE_E2E_DEPLOYMENT_ID" = "sandbox-e2e-ten-account-v13"
test "$DESIRE_E2E_RELEASE_ID" = "release-e2e-ten-account-v13-iam37-demand10-trust7"
test ! -e "$DESIRE_E2E_INPUT_ROOT"
test ! -L "$DESIRE_E2E_INPUT_ROOT"

DESIRE_E2E_CONTAINER_PREFIX="${DESIRE_E2E_PROJECT}-"
DESIRE_E2E_RESOURCE_PREFIX="${DESIRE_E2E_PROJECT}_"
DESIRE_E2E_PROJECT_CONTAINER_IDS="$(docker container ls -aq --filter "label=com.docker.compose.project=$DESIRE_E2E_PROJECT")"
DESIRE_E2E_PROJECT_NETWORK_IDS="$(docker network ls -q --filter "label=com.docker.compose.project=$DESIRE_E2E_PROJECT")"
DESIRE_E2E_PROJECT_VOLUME_IDS="$(docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_E2E_PROJECT")"
DESIRE_E2E_CONTAINER_PREFIX_MATCHES="$(docker container ls -a --format '{{.Names}}' | awk -v prefix="$DESIRE_E2E_CONTAINER_PREFIX" 'index($0, prefix) == 1 { print }')"
DESIRE_E2E_NETWORK_PREFIX_MATCHES="$(docker network ls --format '{{.Name}}' | awk -v prefix="$DESIRE_E2E_RESOURCE_PREFIX" 'index($0, prefix) == 1 { print }')"
DESIRE_E2E_VOLUME_PREFIX_MATCHES="$(docker volume ls --format '{{.Name}}' | awk -v prefix="$DESIRE_E2E_RESOURCE_PREFIX" 'index($0, prefix) == 1 { print }')"
DESIRE_E2E_PLATFORM_TAG_IDS="$(docker image ls --quiet "desire-supply-platform:$DESIRE_IMAGE_TAG")"
DESIRE_E2E_WEB_TAG_IDS="$(docker image ls --quiet "desire-supply-web:$DESIRE_IMAGE_TAG")"
DESIRE_E2E_EDGE_TAG_IDS="$(docker image ls --quiet "desire-supply-edge:$DESIRE_IMAGE_TAG")"
if DESIRE_E2E_PORT_443_LISTENERS="$(lsof -nP -iTCP@127.0.0.1:443 -sTCP:LISTEN -t)"; then
  :
else
  test "$?" = "1"
fi
test -z "$DESIRE_E2E_PROJECT_CONTAINER_IDS"
test -z "$DESIRE_E2E_PROJECT_NETWORK_IDS"
test -z "$DESIRE_E2E_PROJECT_VOLUME_IDS"
test -z "$DESIRE_E2E_CONTAINER_PREFIX_MATCHES"
test -z "$DESIRE_E2E_NETWORK_PREFIX_MATCHES"
test -z "$DESIRE_E2E_VOLUME_PREFIX_MATCHES"
test -z "$DESIRE_E2E_PLATFORM_TAG_IDS"
test -z "$DESIRE_E2E_WEB_TAG_IDS"
test -z "$DESIRE_E2E_EDGE_TAG_IDS"
test -z "$DESIRE_E2E_PORT_443_LISTENERS"

docker info --format '{{ json .DefaultAddressPools }}'
docker network ls -q | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
netstat -rn
python3 -B scripts/preflight_docker_hub_manifests.py

original_umask="$(umask)"
umask 077
mkdir -m 0700 -- "$DESIRE_E2E_INPUT_ROOT"
test -d "$DESIRE_E2E_INPUT_ROOT"
test ! -L "$DESIRE_E2E_INPUT_ROOT"
test "$(stat -f '%Lp|%u|%g' "$DESIRE_E2E_INPUT_ROOT")" = "700|$(id -u)|$(id -g)"

DESIRE_E2E_INPUT_RESULT="$(python3 -B scripts/prepare_internal_sandbox_inputs.py create --output-root "$DESIRE_E2E_INPUT_ROOT")"
test "$DESIRE_E2E_INPUT_RESULT" = '{"status":"INTERNAL_SANDBOX_INPUTS_CREATED"}'
DESIRE_E2E_TLS_RESULT="$(python3 -B scripts/manage_internal_sandbox_tls.py create --output-dir "$DESIRE_E2E_INPUT_ROOT/internal-sandbox-tls")"
test "$DESIRE_E2E_TLS_RESULT" = '{"status":"INTERNAL_SANDBOX_TLS_CREATED"}'
DESIRE_E2E_BUNDLE_RESULT="$(PYTHONPATH="$PWD/platform/src" "$PWD/platform/.venv/bin/python" -m desire_platform.deployment.internal_sandbox_bundle create --output-dir "$DESIRE_E2E_BUNDLE_DIR" --oidc-issuer "https://identity.example.test" --oidc-client-id "desire-internal-sandbox" --oidc-redirect-uri "https://pilot.example.test/v1/auth/oidc/callback" --oidc-client-secret-file "$DESIRE_E2E_INPUT_ROOT/oidc-client-secret" --deployment-id "$DESIRE_E2E_DEPLOYMENT_ID" --release-id "$DESIRE_E2E_RELEASE_ID")"
test "$DESIRE_E2E_BUNDLE_RESULT" = '{"database_credential_count":11,"key_count":24,"output_dir":"/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/internal-sandbox-bundle-iam37-demand10-trust7","secret_count":35,"status":"INTERNAL_SANDBOX_BUNDLE_CREATED"}'
DESIRE_E2E_COMPOSE_INPUT_RESULT="$(python3 -B scripts/prepare_internal_sandbox_compose_inputs.py create --input-root "$DESIRE_E2E_INPUT_ROOT" --image-tag "$DESIRE_IMAGE_TAG" --bundle-dir-name "$DESIRE_E2E_BUNDLE_NAME" --ingress-subnet "$DESIRE_E2E_INGRESS_SUBNET" --oidc-subnet "$DESIRE_E2E_OIDC_SUBNET" --app-subnet "$DESIRE_E2E_APP_SUBNET" --data-subnet "$DESIRE_E2E_DATA_SUBNET")"
test "$DESIRE_E2E_COMPOSE_INPUT_RESULT" = '{"status":"INTERNAL_SANDBOX_COMPOSE_INPUTS_CREATED"}'
test "$(python3 -B scripts/prepare_internal_sandbox_inputs.py verify --input-root "$DESIRE_E2E_INPUT_ROOT")" = '{"status":"INTERNAL_SANDBOX_INPUTS_VERIFIED"}'
test "$(python3 -B scripts/manage_internal_sandbox_tls.py verify --input-dir "$DESIRE_E2E_INPUT_ROOT/internal-sandbox-tls")" = '{"status":"INTERNAL_SANDBOX_TLS_VERIFIED"}'
test "$(python3 -B scripts/prepare_internal_sandbox_compose_inputs.py verify --input-root "$DESIRE_E2E_INPUT_ROOT" --image-tag "$DESIRE_IMAGE_TAG" --bundle-dir-name "$DESIRE_E2E_BUNDLE_NAME" --ingress-subnet "$DESIRE_E2E_INGRESS_SUBNET" --oidc-subnet "$DESIRE_E2E_OIDC_SUBNET" --app-subnet "$DESIRE_E2E_APP_SUBNET" --data-subnet "$DESIRE_E2E_DATA_SUBNET")" = '{"status":"INTERNAL_SANDBOX_COMPOSE_INPUTS_VERIFIED"}'

mkdir -m 0700 -- "$DESIRE_E2E_EVIDENCE_DIR"
test -d "$DESIRE_E2E_EVIDENCE_DIR"
test ! -L "$DESIRE_E2E_EVIDENCE_DIR"
test "$(stat -f '%Lp|%u|%g' "$DESIRE_E2E_EVIDENCE_DIR")" = "700|$(id -u)|$(id -g)"
test ! -e "$DESIRE_E2E_STATE"
test ! -L "$DESIRE_E2E_STATE"
test ! -e "$DESIRE_E2E_JOURNEY_RESULT"
test ! -L "$DESIRE_E2E_JOURNEY_RESULT"
test ! -e "$DESIRE_E2E_RESTART_1_RESULT"
test ! -L "$DESIRE_E2E_RESTART_1_RESULT"
test ! -e "$DESIRE_E2E_RESTART_2_RESULT"
test ! -L "$DESIRE_E2E_RESTART_2_RESULT"

compose_v13() {
  docker compose \
    --project-name "$DESIRE_E2E_PROJECT" \
    --env-file "$DESIRE_E2E_INPUT_ROOT/compose.env" \
    -f "$PWD/compose.yaml" \
    -f "$DESIRE_E2E_INPUT_ROOT/compose.ipam.yaml" "$@"
}

compose_v13 config --quiet
compose_v13 build api web edge
DESIRE_E2E_PLATFORM_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "desire-supply-platform:$DESIRE_IMAGE_TAG")"
DESIRE_E2E_WEB_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "desire-supply-web:$DESIRE_IMAGE_TAG")"
DESIRE_E2E_EDGE_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "desire-supply-edge:$DESIRE_IMAGE_TAG")"
test -n "$DESIRE_E2E_PLATFORM_IMAGE_ID"
test -n "$DESIRE_E2E_WEB_IMAGE_ID"
test -n "$DESIRE_E2E_EDGE_IMAGE_ID"

compose_v13 up -d --wait --wait-timeout 120 synthetic-oidc edge
compose_v13 up -d --wait --wait-timeout 120 db
compose_v13 up -d --no-deps migrate
DESIRE_E2E_MIGRATE_ID="$(compose_v13 ps --all --quiet migrate)"
test -n "$DESIRE_E2E_MIGRATE_ID"
test "$(docker wait "$DESIRE_E2E_MIGRATE_ID")" = "0"
test "$(docker inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_MIGRATE_ID")" = "exited|0|0"
docker start "$DESIRE_E2E_MIGRATE_ID"
test "$(docker wait "$DESIRE_E2E_MIGRATE_ID")" = "0"
test "$(docker inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_MIGRATE_ID")" = "exited|0|0"

export DESIRE_E2E_FRESH_SCHEMA_READY='{"catalogs":{"demand":{"applied_versions":[1,2,3,4,5,6,7,8,9,10],"skipped_versions":[]},"iam":{"applied_versions":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37],"skipped_versions":[]},"profile":{"applied_versions":[1,2,3],"skipped_versions":[]},"taxonomy":{"applied_versions":[1,2],"skipped_versions":[]},"trust":{"applied_versions":[1,2,3,4,5,6,7],"skipped_versions":[]}},"status":"SCHEMA_READY"}'
export DESIRE_E2E_REPLAY_SCHEMA_READY='{"catalogs":{"demand":{"applied_versions":[],"skipped_versions":[1,2,3,4,5,6,7,8,9,10]},"iam":{"applied_versions":[],"skipped_versions":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37]},"profile":{"applied_versions":[],"skipped_versions":[1,2,3]},"taxonomy":{"applied_versions":[],"skipped_versions":[1,2]},"trust":{"applied_versions":[],"skipped_versions":[1,2,3,4,5,6,7]}},"status":"SCHEMA_READY"}'
DESIRE_E2E_MIGRATE_LOG="$(compose_v13 logs --no-color --no-log-prefix migrate)"
test "$(printf '%s\n' "$DESIRE_E2E_MIGRATE_LOG" | sed '/^$/d' | wc -l | tr -d ' ')" = "2"
test "$(printf '%s\n' "$DESIRE_E2E_MIGRATE_LOG" | grep -Fxc "$DESIRE_E2E_FRESH_SCHEMA_READY")" = "1"
test "$(printf '%s\n' "$DESIRE_E2E_MIGRATE_LOG" | grep -Fxc "$DESIRE_E2E_REPLAY_SCHEMA_READY")" = "1"
test -z "$(printf '%s\n' "$DESIRE_E2E_MIGRATE_LOG" | grep -F '"status":"BLOCKED"' || true)"

compose_v13 up -d --no-deps taxonomy-seed
DESIRE_E2E_TAXONOMY_ID="$(compose_v13 ps --all --quiet taxonomy-seed)"
test -n "$DESIRE_E2E_TAXONOMY_ID"
test "$(docker wait "$DESIRE_E2E_TAXONOMY_ID")" = "0"
test "$(docker inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_TAXONOMY_ID")" = "exited|0|0"
test "$(compose_v13 logs --no-color --no-log-prefix taxonomy-seed)" = '{"manifest_sha256":"418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d","replayed":false,"status":"INTERNAL_SANDBOX_TAXONOMY_SEED_READY","taxonomy_bundle_id":"50000000-0000-4000-8000-000000000001"}'

compose_v13 up -d --no-deps online-credentials-reconcile
DESIRE_E2E_RECONCILE_ID="$(compose_v13 ps --all --quiet online-credentials-reconcile)"
test -n "$DESIRE_E2E_RECONCILE_ID"
test "$(docker wait "$DESIRE_E2E_RECONCILE_ID")" = "0"
test "$(docker inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_RECONCILE_ID")" = "exited|0|0"
test "$(compose_v13 logs --no-color --no-log-prefix online-credentials-reconcile)" = '{"action":"RECONCILE","online_role_count":11,"status":"ONLINE_CREDENTIALS_READY"}'

compose_v13 up -d --no-deps online-credentials-verify
DESIRE_E2E_CREDENTIAL_VERIFY_ID="$(compose_v13 ps --all --quiet online-credentials-verify)"
test -n "$DESIRE_E2E_CREDENTIAL_VERIFY_ID"
test "$(docker wait "$DESIRE_E2E_CREDENTIAL_VERIFY_ID")" = "0"
test "$(docker inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_CREDENTIAL_VERIFY_ID")" = "exited|0|0"
test "$(compose_v13 logs --no-color --no-log-prefix online-credentials-verify)" = '{"action":"VERIFY","online_role_count":11,"status":"ONLINE_CREDENTIALS_READY"}'

compose_v13 up -d --no-deps identity-bootstrap
DESIRE_E2E_IDENTITY_ID="$(compose_v13 ps --all --quiet identity-bootstrap)"
test -n "$DESIRE_E2E_IDENTITY_ID"
test "$(docker wait "$DESIRE_E2E_IDENTITY_ID")" = "0"
test "$(docker inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_IDENTITY_ID")" = "exited|0|0"
DESIRE_E2E_IDENTITY_LOG="$(compose_v13 logs --no-color --no-log-prefix identity-bootstrap)"
test "$(printf '%s\n' "$DESIRE_E2E_IDENTITY_LOG" | sed '/^$/d' | wc -l | tr -d ' ')" = "1"
test "$(printf '%s\n' "$DESIRE_E2E_IDENTITY_LOG" | python3 -c 'import json,sys; value=json.load(sys.stdin); print("|".join((value.get("status",""),value.get("apply_outcome",""),value.get("verify_outcome",""))))')" = "IDENTITY_BOOTSTRAP_ORCHESTRATION_READY|APPLIED|VERIFIED"

compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 api
compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 web
test "$(compose_v13 ps --all --quiet | wc -l | tr -d ' ')" = "10"
test "$(compose_v13 exec -T api python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2).read().decode())")" = '{"deployment_mode":"INTERNAL_SANDBOX","external_participants":"DISABLED","g1":"NO-GO","g2":"NO-GO","status":"READY"}'
test "$(docker image inspect --format '{{.Id}}' "desire-supply-platform:$DESIRE_IMAGE_TAG")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"
test "$(docker image inspect --format '{{.Id}}' "desire-supply-web:$DESIRE_IMAGE_TAG")" = "$DESIRE_E2E_WEB_IMAGE_ID"
test "$(docker image inspect --format '{{.Id}}' "desire-supply-edge:$DESIRE_IMAGE_TAG")" = "$DESIRE_E2E_EDGE_IMAGE_ID"
test "$(docker inspect --format '{{.Image}}' "$(compose_v13 ps --quiet api)")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"
test "$(docker inspect --format '{{.Image}}' "$(compose_v13 ps --quiet web)")" = "$DESIRE_E2E_WEB_IMAGE_ID"
test "$(docker inspect --format '{{.Image}}' "$(compose_v13 ps --quiet edge)")" = "$DESIRE_E2E_EDGE_IMAGE_ID"
test "$(docker inspect --format '{{.Image}}' "$(compose_v13 ps --quiet synthetic-oidc)")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"
test "$(docker inspect --format '{{.Image}}' "$DESIRE_E2E_MIGRATE_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"
test "$(docker inspect --format '{{.Image}}' "$DESIRE_E2E_TAXONOMY_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"
test "$(docker inspect --format '{{.Image}}' "$DESIRE_E2E_RECONCILE_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"
test "$(docker inspect --format '{{.Image}}' "$DESIRE_E2E_CREDENTIAL_VERIFY_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"
test "$(docker inspect --format '{{.Image}}' "$DESIRE_E2E_IDENTITY_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"

DESIRE_E2E_DB_ID="$(compose_v13 ps --quiet db)"
DESIRE_E2E_OIDC_ID="$(compose_v13 ps --quiet synthetic-oidc)"
DESIRE_E2E_EDGE_ID="$(compose_v13 ps --quiet edge)"
DESIRE_E2E_API_ID="$(compose_v13 ps --quiet api)"
DESIRE_E2E_WEB_ID="$(compose_v13 ps --quiet web)"
test -n "$DESIRE_E2E_DB_ID"
test -n "$DESIRE_E2E_OIDC_ID"
test -n "$DESIRE_E2E_EDGE_ID"
test -n "$DESIRE_E2E_API_ID"
test -n "$DESIRE_E2E_WEB_ID"
DESIRE_E2E_DB_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_DB_ID")"
DESIRE_E2E_OIDC_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_OIDC_ID")"
DESIRE_E2E_EDGE_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_EDGE_ID")"
DESIRE_E2E_API_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_API_ID")"
DESIRE_E2E_WEB_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_WEB_ID")"
test -n "$DESIRE_E2E_DB_STARTED_AT"
test -n "$DESIRE_E2E_OIDC_STARTED_AT"
test -n "$DESIRE_E2E_EDGE_STARTED_AT"
test -n "$DESIRE_E2E_API_STARTED_AT"
test -n "$DESIRE_E2E_WEB_STARTED_AT"
DESIRE_E2E_MIGRATE_SNAPSHOT="$(docker inspect --format '{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_MIGRATE_ID")"
DESIRE_E2E_TAXONOMY_SNAPSHOT="$(docker inspect --format '{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_TAXONOMY_ID")"
DESIRE_E2E_RECONCILE_SNAPSHOT="$(docker inspect --format '{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_RECONCILE_ID")"
DESIRE_E2E_CREDENTIAL_VERIFY_SNAPSHOT="$(docker inspect --format '{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_CREDENTIAL_VERIFY_ID")"
DESIRE_E2E_IDENTITY_SNAPSHOT="$(docker inspect --format '{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_IDENTITY_ID")"
DESIRE_E2E_MIGRATE_LOG_SHA="$(compose_v13 logs --no-color --no-log-prefix migrate | shasum -a 256 | awk '{print $1}')"
DESIRE_E2E_TAXONOMY_LOG_SHA="$(compose_v13 logs --no-color --no-log-prefix taxonomy-seed | shasum -a 256 | awk '{print $1}')"
DESIRE_E2E_RECONCILE_LOG_SHA="$(compose_v13 logs --no-color --no-log-prefix online-credentials-reconcile | shasum -a 256 | awk '{print $1}')"
DESIRE_E2E_CREDENTIAL_VERIFY_LOG_SHA="$(compose_v13 logs --no-color --no-log-prefix online-credentials-verify | shasum -a 256 | awk '{print $1}')"
DESIRE_E2E_IDENTITY_LOG_SHA="$(compose_v13 logs --no-color --no-log-prefix identity-bootstrap | shasum -a 256 | awk '{print $1}')"
DESIRE_E2E_INGRESS_NETWORK_ID="$(docker network inspect --format '{{.Id}}' "${DESIRE_E2E_PROJECT}_ingress")"
DESIRE_E2E_OIDC_NETWORK_ID="$(docker network inspect --format '{{.Id}}' "${DESIRE_E2E_PROJECT}_oidc-backend")"
DESIRE_E2E_APP_NETWORK_ID="$(docker network inspect --format '{{.Id}}' "${DESIRE_E2E_PROJECT}_app")"
DESIRE_E2E_DATA_NETWORK_ID="$(docker network inspect --format '{{.Id}}' "${DESIRE_E2E_PROJECT}_data")"
DESIRE_E2E_DATA_VOLUME="${DESIRE_E2E_PROJECT}_postgres-data"
DESIRE_E2E_DATA_VOLUME_CREATED_AT="$(docker volume inspect --format '{{.CreatedAt}}' "$DESIRE_E2E_DATA_VOLUME")"
# END CURRENT_HEAD_V13_FRESH_RUNBOOK
```

只有 fresh 段全部 GREEN，才允许执行一次 journey 和两轮完整 restart。runner 把 state 与每轮
结果以 absolute path、`O_EXCL`、0600 落到已忽略且不进入 Docker build context 的 0700
evidence 目录；同一结果仍镜像到 stdout。restart 只读同一 state，不生成第二套业务事实：

```bash
# BEGIN CURRENT_HEAD_V13_JOURNEY_RESTART
python3 -B scripts/run_internal_sandbox_e2e.py journey \
  --ca-file "$DESIRE_E2E_INPUT_ROOT/internal-sandbox-tls/root-ca.pem" \
  --state-output "$DESIRE_E2E_STATE" \
  --result-output "$DESIRE_E2E_JOURNEY_RESULT"
test -f "$DESIRE_E2E_STATE"
test ! -L "$DESIRE_E2E_STATE"
test "$(stat -f '%Lp|%u|%g|%l' "$DESIRE_E2E_STATE")" = "600|$(id -u)|$(id -g)|1"
test -f "$DESIRE_E2E_JOURNEY_RESULT"
test ! -L "$DESIRE_E2E_JOURNEY_RESULT"
test "$(stat -f '%Lp|%u|%g|%l' "$DESIRE_E2E_JOURNEY_RESULT")" = "600|$(id -u)|$(id -g)|1"
test "$(wc -l < "$DESIRE_E2E_JOURNEY_RESULT" | tr -d ' ')" = "1"
python3 -B -c 'import json,sys; value=json.load(open(sys.argv[1],encoding="utf-8")); raise SystemExit(0 if value.get("status")=="TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN" else 1)' "$DESIRE_E2E_JOURNEY_RESULT"

DESIRE_E2E_STATE_STAT="$(stat -f '%Lp|%u|%g|%z|%m|%c|%i|%l' "$DESIRE_E2E_STATE")"
DESIRE_E2E_STATE_SHA="$(shasum -a 256 "$DESIRE_E2E_STATE" | awk '{print $1}')"

assert_v13_preserved() {
  test "$(compose_v13 ps --all --quiet | wc -l | tr -d ' ')" = "10"
  test "$(compose_v13 ps --quiet db)" = "$DESIRE_E2E_DB_ID"
  test "$(compose_v13 ps --quiet synthetic-oidc)" = "$DESIRE_E2E_OIDC_ID"
  test "$(compose_v13 ps --quiet edge)" = "$DESIRE_E2E_EDGE_ID"
  test "$(compose_v13 ps --quiet api)" = "$DESIRE_E2E_API_ID"
  test "$(compose_v13 ps --quiet web)" = "$DESIRE_E2E_WEB_ID"
  test "$(compose_v13 ps --all --quiet migrate)" = "$DESIRE_E2E_MIGRATE_ID"
  test "$(compose_v13 ps --all --quiet taxonomy-seed)" = "$DESIRE_E2E_TAXONOMY_ID"
  test "$(compose_v13 ps --all --quiet online-credentials-reconcile)" = "$DESIRE_E2E_RECONCILE_ID"
  test "$(compose_v13 ps --all --quiet online-credentials-verify)" = "$DESIRE_E2E_CREDENTIAL_VERIFY_ID"
  test "$(compose_v13 ps --all --quiet identity-bootstrap)" = "$DESIRE_E2E_IDENTITY_ID"
  test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "$DESIRE_E2E_DB_ID")" = "running|healthy|0"
  test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "$DESIRE_E2E_OIDC_ID")" = "running|healthy|0"
  test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "$DESIRE_E2E_EDGE_ID")" = "running|healthy|0"
  test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "$DESIRE_E2E_API_ID")" = "running|healthy|0"
  test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "$DESIRE_E2E_WEB_ID")" = "running|healthy|0"
  test "$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_DB_ID")" = "$DESIRE_E2E_DB_STARTED_AT"
  test "$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_OIDC_ID")" = "$DESIRE_E2E_OIDC_STARTED_AT"
  test "$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_EDGE_ID")" = "$DESIRE_E2E_EDGE_STARTED_AT"
  test "$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_API_ID")" = "$DESIRE_E2E_API_STARTED_AT"
  test "$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_WEB_ID")" = "$DESIRE_E2E_WEB_STARTED_AT"
  test "$(docker inspect --format '{{.Image}}' "$DESIRE_E2E_API_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"
  test "$(docker inspect --format '{{.Image}}' "$DESIRE_E2E_OIDC_ID")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"
  test "$(docker inspect --format '{{.Image}}' "$DESIRE_E2E_WEB_ID")" = "$DESIRE_E2E_WEB_IMAGE_ID"
  test "$(docker inspect --format '{{.Image}}' "$DESIRE_E2E_EDGE_ID")" = "$DESIRE_E2E_EDGE_IMAGE_ID"
  test "$(docker image inspect --format '{{.Id}}' "desire-supply-platform:$DESIRE_IMAGE_TAG")" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"
  test "$(docker image inspect --format '{{.Id}}' "desire-supply-web:$DESIRE_IMAGE_TAG")" = "$DESIRE_E2E_WEB_IMAGE_ID"
  test "$(docker image inspect --format '{{.Id}}' "desire-supply-edge:$DESIRE_IMAGE_TAG")" = "$DESIRE_E2E_EDGE_IMAGE_ID"
  test "$(docker inspect --format '{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_MIGRATE_ID")" = "$DESIRE_E2E_MIGRATE_SNAPSHOT"
  test "$(docker inspect --format '{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_TAXONOMY_ID")" = "$DESIRE_E2E_TAXONOMY_SNAPSHOT"
  test "$(docker inspect --format '{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_RECONCILE_ID")" = "$DESIRE_E2E_RECONCILE_SNAPSHOT"
  test "$(docker inspect --format '{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_CREDENTIAL_VERIFY_ID")" = "$DESIRE_E2E_CREDENTIAL_VERIFY_SNAPSHOT"
  test "$(docker inspect --format '{{.Id}}|{{.Image}}|{{.State.StartedAt}}|{{.State.FinishedAt}}|{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_E2E_IDENTITY_ID")" = "$DESIRE_E2E_IDENTITY_SNAPSHOT"
  test "$(compose_v13 logs --no-color --no-log-prefix migrate | shasum -a 256 | awk '{print $1}')" = "$DESIRE_E2E_MIGRATE_LOG_SHA"
  test "$(compose_v13 logs --no-color --no-log-prefix taxonomy-seed | shasum -a 256 | awk '{print $1}')" = "$DESIRE_E2E_TAXONOMY_LOG_SHA"
  test "$(compose_v13 logs --no-color --no-log-prefix online-credentials-reconcile | shasum -a 256 | awk '{print $1}')" = "$DESIRE_E2E_RECONCILE_LOG_SHA"
  test "$(compose_v13 logs --no-color --no-log-prefix online-credentials-verify | shasum -a 256 | awk '{print $1}')" = "$DESIRE_E2E_CREDENTIAL_VERIFY_LOG_SHA"
  test "$(compose_v13 logs --no-color --no-log-prefix identity-bootstrap | shasum -a 256 | awk '{print $1}')" = "$DESIRE_E2E_IDENTITY_LOG_SHA"
  test "$(docker network inspect --format '{{.Id}}' "${DESIRE_E2E_PROJECT}_ingress")" = "$DESIRE_E2E_INGRESS_NETWORK_ID"
  test "$(docker network inspect --format '{{.Id}}' "${DESIRE_E2E_PROJECT}_oidc-backend")" = "$DESIRE_E2E_OIDC_NETWORK_ID"
  test "$(docker network inspect --format '{{.Id}}' "${DESIRE_E2E_PROJECT}_app")" = "$DESIRE_E2E_APP_NETWORK_ID"
  test "$(docker network inspect --format '{{.Id}}' "${DESIRE_E2E_PROJECT}_data")" = "$DESIRE_E2E_DATA_NETWORK_ID"
  test "$(docker volume inspect --format '{{.CreatedAt}}' "$DESIRE_E2E_DATA_VOLUME")" = "$DESIRE_E2E_DATA_VOLUME_CREATED_AT"
  test "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}|{{.Name}}{{end}}{{end}}' "$DESIRE_E2E_DB_ID")" = "volume|$DESIRE_E2E_DATA_VOLUME"
  test "$(stat -f '%Lp|%u|%g|%z|%m|%c|%i|%l' "$DESIRE_E2E_STATE")" = "$DESIRE_E2E_STATE_STAT"
  test "$(shasum -a 256 "$DESIRE_E2E_STATE" | awk '{print $1}')" = "$DESIRE_E2E_STATE_SHA"
}

assert_v13_stopped() {
  test "$(compose_v13 ps --all --quiet db)" = "$DESIRE_E2E_DB_ID"
  test "$(compose_v13 ps --all --quiet synthetic-oidc)" = "$DESIRE_E2E_OIDC_ID"
  test "$(compose_v13 ps --all --quiet edge)" = "$DESIRE_E2E_EDGE_ID"
  test "$(compose_v13 ps --all --quiet api)" = "$DESIRE_E2E_API_ID"
  test "$(compose_v13 ps --all --quiet web)" = "$DESIRE_E2E_WEB_ID"
  test "$(docker inspect --format '{{.State.Status}}|{{.RestartCount}}' "$DESIRE_E2E_DB_ID")" = "exited|0"
  test "$(docker inspect --format '{{.State.Status}}|{{.RestartCount}}' "$DESIRE_E2E_OIDC_ID")" = "exited|0"
  test "$(docker inspect --format '{{.State.Status}}|{{.RestartCount}}' "$DESIRE_E2E_EDGE_ID")" = "exited|0"
  test "$(docker inspect --format '{{.State.Status}}|{{.RestartCount}}' "$DESIRE_E2E_API_ID")" = "exited|0"
  test "$(docker inspect --format '{{.State.Status}}|{{.RestartCount}}' "$DESIRE_E2E_WEB_ID")" = "exited|0"
}

advance_v13_started_at() {
  DESIRE_E2E_DB_NEXT_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_DB_ID")"
  DESIRE_E2E_OIDC_NEXT_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_OIDC_ID")"
  DESIRE_E2E_EDGE_NEXT_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_EDGE_ID")"
  DESIRE_E2E_API_NEXT_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_API_ID")"
  DESIRE_E2E_WEB_NEXT_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_E2E_WEB_ID")"
  test -n "$DESIRE_E2E_DB_NEXT_STARTED_AT"
  test -n "$DESIRE_E2E_OIDC_NEXT_STARTED_AT"
  test -n "$DESIRE_E2E_EDGE_NEXT_STARTED_AT"
  test -n "$DESIRE_E2E_API_NEXT_STARTED_AT"
  test -n "$DESIRE_E2E_WEB_NEXT_STARTED_AT"
  test "$DESIRE_E2E_DB_NEXT_STARTED_AT" != "$DESIRE_E2E_DB_STARTED_AT"
  test "$DESIRE_E2E_OIDC_NEXT_STARTED_AT" != "$DESIRE_E2E_OIDC_STARTED_AT"
  test "$DESIRE_E2E_EDGE_NEXT_STARTED_AT" != "$DESIRE_E2E_EDGE_STARTED_AT"
  test "$DESIRE_E2E_API_NEXT_STARTED_AT" != "$DESIRE_E2E_API_STARTED_AT"
  test "$DESIRE_E2E_WEB_NEXT_STARTED_AT" != "$DESIRE_E2E_WEB_STARTED_AT"
  DESIRE_E2E_DB_STARTED_AT="$DESIRE_E2E_DB_NEXT_STARTED_AT"
  DESIRE_E2E_OIDC_STARTED_AT="$DESIRE_E2E_OIDC_NEXT_STARTED_AT"
  DESIRE_E2E_EDGE_STARTED_AT="$DESIRE_E2E_EDGE_NEXT_STARTED_AT"
  DESIRE_E2E_API_STARTED_AT="$DESIRE_E2E_API_NEXT_STARTED_AT"
  DESIRE_E2E_WEB_STARTED_AT="$DESIRE_E2E_WEB_NEXT_STARTED_AT"
}

assert_v13_preserved
compose_v13 stop web
compose_v13 stop api
compose_v13 stop edge
compose_v13 stop synthetic-oidc
compose_v13 stop db
assert_v13_stopped
compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 db
compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 synthetic-oidc
compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 edge
compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 api
compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 web
advance_v13_started_at
assert_v13_preserved
python3 -B scripts/run_internal_sandbox_e2e.py verify-restart \
  --ca-file "$DESIRE_E2E_INPUT_ROOT/internal-sandbox-tls/root-ca.pem" \
  --state-file "$DESIRE_E2E_STATE" \
  --result-output "$DESIRE_E2E_RESTART_1_RESULT"
test -f "$DESIRE_E2E_RESTART_1_RESULT"
test ! -L "$DESIRE_E2E_RESTART_1_RESULT"
test "$(stat -f '%Lp|%u|%g|%l' "$DESIRE_E2E_RESTART_1_RESULT")" = "600|$(id -u)|$(id -g)|1"
test "$(wc -l < "$DESIRE_E2E_RESTART_1_RESULT" | tr -d ' ')" = "1"
python3 -B -c 'import json,sys; value=json.load(open(sys.argv[1],encoding="utf-8")); raise SystemExit(0 if value.get("status")=="TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN" else 1)' "$DESIRE_E2E_RESTART_1_RESULT"
assert_v13_preserved

compose_v13 stop web
compose_v13 stop api
compose_v13 stop edge
compose_v13 stop synthetic-oidc
compose_v13 stop db
assert_v13_stopped
compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 db
compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 synthetic-oidc
compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 edge
compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 api
compose_v13 up -d --no-deps --no-recreate --wait --wait-timeout 120 web
advance_v13_started_at
assert_v13_preserved
python3 -B scripts/run_internal_sandbox_e2e.py verify-restart \
  --ca-file "$DESIRE_E2E_INPUT_ROOT/internal-sandbox-tls/root-ca.pem" \
  --state-file "$DESIRE_E2E_STATE" \
  --result-output "$DESIRE_E2E_RESTART_2_RESULT"
test -f "$DESIRE_E2E_RESTART_2_RESULT"
test ! -L "$DESIRE_E2E_RESTART_2_RESULT"
test "$(stat -f '%Lp|%u|%g|%l' "$DESIRE_E2E_RESTART_2_RESULT")" = "600|$(id -u)|$(id -g)|1"
test "$(wc -l < "$DESIRE_E2E_RESTART_2_RESULT" | tr -d ' ')" = "1"
python3 -B -c 'import json,sys; value=json.load(open(sys.argv[1],encoding="utf-8")); raise SystemExit(0 if value.get("status")=="TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN" else 1)' "$DESIRE_E2E_RESTART_2_RESULT"
assert_v13_preserved
umask "$original_umask"
# END CURRENT_HEAD_V13_JOURNEY_RESTART
```

只有两轮 result 分别精确为 `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`，且五个持久容器、五个
one-shot 容器及其日志、四个 network、`postgres-data` volume、三个 production image ID
和 state 的 stat/SHA-256 全部保持，才可进入 v13 source backup。HTTP runner 仍不等于桌面/
移动浏览器视觉 QA；该门禁继续保持未完成。

### 4.8 备份与隔离恢复检查

PostgreSQL 18.4 镜像声明 `VOLUME /var/lib/postgresql`。base `db` 与 restore target 继续把
named volume 挂到 child `/var/lib/postgresql/data`，并保持
`PGDATA=/var/lib/postgresql/data/pgdata`；base `db`、backup client、restore target 和
restore verify 都必须以参数 `rw,nosuid,nodev,noexec,size=1m` 的显式 tmpfs 覆盖 parent
`/var/lib/postgresql`，避免隐式匿名 parent volume。不得把 named volume 的 target 改到 `/var/lib/postgresql`；
parent tmpfs 与 child named mount 是兼容既有数据布局的有意嵌套。

#### 4.8.1 当前头部 v13 源侧备份（一次性）

本标题是 verifier 冻结的历史 v13 标签，不是 current v27 操作入口；v26 也已是冻结历史。source backup 只能加入已经
存在且 healthy 的 v13 `db`；不得让 operations overlay 创建、
替换或启动一个空数据库。下列 wrapper 精确绑定 source project、v13 env、base Compose、v13
IPAM overlay 与 operations overlay。它不得改成 restore project，也不得省略任一文件。
仓库根 `.gitignore` 与 `.dockerignore` 都以唯一、锚定的 `/backups/` 排除本机备份树，避免
artifact 意外进入 VCS 或 Docker build context；这种排除不是加密或 offsite 保护：

```bash
# BEGIN CURRENT_HEAD_V13_BACKUP
set -eu
set -o pipefail
test "$(pwd -P)" = "/Users/shiyaozhang/Developer/desire-supply"
test -z "${COMPOSE_PROJECT_NAME+x}"
test -z "${COMPOSE_COMPATIBILITY+x}"
test -z "${DESIRE_DB_PASSWORD_FILE+x}"
test -z "${DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE+x}"
test -z "${DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE+x}"
test -z "${DESIRE_IDENTITY_SOURCE_DIR+x}"
test -z "${DESIRE_INTERNAL_SANDBOX_TLS_DIR+x}"
test -z "${DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR+x}"
export DESIRE_DATABASE_SOURCE_PROJECT="desire-supply-e2e-ten-account-v13"
export SOURCE_DATA_NETWORK="desire-supply-e2e-ten-account-v13_data"
export SOURCE_DATA_VOLUME="desire-supply-e2e-ten-account-v13_postgres-data"
export DESIRE_DATABASE_BACKUP_PARENT="$PWD/backups"
export DESIRE_DATABASE_BACKUP_SANDBOX_PARENT="$PWD/backups/internal-sandbox"
export DESIRE_DATABASE_BACKUP_DIR="/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v13drill01"
export DESIRE_DATABASE_BACKUP_BASENAME="v13-iam37-profile3-demand10-trust7-taxonomy2-drill01"
DESIRE_DATABASE_OPERATIONS_UID="$(id -u)"
DESIRE_DATABASE_OPERATIONS_GID="$(id -g)"
export DESIRE_DATABASE_OPERATIONS_UID DESIRE_DATABASE_OPERATIONS_GID

compose_v13_backup() {
  docker compose \
    --project-name "$DESIRE_DATABASE_SOURCE_PROJECT" \
    --env-file "$PWD/secrets/e2e-ten-account-v13/compose.env" \
    -f "$PWD/compose.yaml" \
    -f "$PWD/secrets/e2e-ten-account-v13/compose.ipam.yaml" \
    -f "$PWD/deploy/postgres-operations.compose.yaml" \
    --profile database-backup "$@"
}

compose_v13_backup config --quiet
test "$(compose_v13_backup ps --all --quiet db | wc -l | tr -d ' ')" = 1
test "$(compose_v13_backup ps --all --quiet api | wc -l | tr -d ' ')" = 1
SOURCE_DB_CONTAINER_ID="$(compose_v13_backup ps --all --quiet db)"
SOURCE_API_CONTAINER_ID="$(compose_v13_backup ps --all --quiet api)"
test -n "$SOURCE_DB_CONTAINER_ID"
test -n "$SOURCE_API_CONTAINER_ID"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}' "$SOURCE_DB_CONTAINER_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|db"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}' "$SOURCE_API_CONTAINER_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|api"
test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}' "$SOURCE_DB_CONTAINER_ID")" = "running|healthy"
test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "$SOURCE_API_CONTAINER_ID")" = "running|healthy|0"
test "$(docker network inspect --format '{{ index .Labels "com.docker.compose.project" }}|{{ index .Labels "com.docker.compose.network" }}' "$SOURCE_DATA_NETWORK")" = "$DESIRE_DATABASE_SOURCE_PROJECT|data"
test "$(docker volume inspect --format '{{ index .Labels "com.docker.compose.project" }}|{{ index .Labels "com.docker.compose.volume" }}' "$SOURCE_DATA_VOLUME")" = "$DESIRE_DATABASE_SOURCE_PROJECT|postgres-data"
test "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}|{{.Name}}{{end}}{{end}}' "$SOURCE_DB_CONTAINER_ID")" = "volume|$SOURCE_DATA_VOLUME"
SOURCE_DB_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$SOURCE_DB_CONTAINER_ID")"
SOURCE_DB_RESTART_COUNT="$(docker inspect --format '{{.RestartCount}}' "$SOURCE_DB_CONTAINER_ID")"
SOURCE_DB_IMAGE_ID="$(docker inspect --format '{{.Image}}' "$SOURCE_DB_CONTAINER_ID")"
SOURCE_API_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$SOURCE_API_CONTAINER_ID")"
SOURCE_API_RESTART_COUNT="$(docker inspect --format '{{.RestartCount}}' "$SOURCE_API_CONTAINER_ID")"
SOURCE_API_IMAGE_ID="$(docker inspect --format '{{.Image}}' "$SOURCE_API_CONTAINER_ID")"
SOURCE_PLATFORM_TAG_ID="$(docker image inspect --format '{{.Id}}' "desire-supply-platform:e2e-ten-account-v13-iam37-demand10-trust7")"
SOURCE_DATA_NETWORK_ID="$(docker network inspect --format '{{.Id}}' "$SOURCE_DATA_NETWORK")"
SOURCE_DATA_VOLUME_CREATED_AT="$(docker volume inspect --format '{{.CreatedAt}}' "$SOURCE_DATA_VOLUME")"
test -n "$SOURCE_DB_STARTED_AT"
test -n "$SOURCE_DB_RESTART_COUNT"
test -n "$SOURCE_DB_IMAGE_ID"
test -n "$SOURCE_API_STARTED_AT"
test -n "$SOURCE_API_RESTART_COUNT"
test -n "$SOURCE_API_IMAGE_ID"
test "$SOURCE_PLATFORM_TAG_ID" = "$SOURCE_API_IMAGE_ID"
test -n "$SOURCE_DATA_NETWORK_ID"
test -n "$SOURCE_DATA_VOLUME_CREATED_AT"
test "$SOURCE_DB_CONTAINER_ID" = "$DESIRE_E2E_DB_ID"
test "$SOURCE_API_CONTAINER_ID" = "$DESIRE_E2E_API_ID"
test "$SOURCE_DB_STARTED_AT" = "$DESIRE_E2E_DB_STARTED_AT"
test "$SOURCE_API_STARTED_AT" = "$DESIRE_E2E_API_STARTED_AT"
test "$SOURCE_DB_RESTART_COUNT" = "0"
test "$SOURCE_API_RESTART_COUNT" = "0"
test "$SOURCE_API_IMAGE_ID" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"
test "$SOURCE_DATA_NETWORK_ID" = "$DESIRE_E2E_DATA_NETWORK_ID"
test "$SOURCE_DATA_VOLUME_CREATED_AT" = "$DESIRE_E2E_DATA_VOLUME_CREATED_AT"
test "$(docker inspect --format '{{with index .NetworkSettings.Networks "desire-supply-e2e-ten-account-v13_data"}}{{.NetworkID}}{{end}}' "$SOURCE_DB_CONTAINER_ID")" = "$SOURCE_DATA_NETWORK_ID"
BACKUP_EXISTING_COMPOSE_IDS="$(compose_v13_backup ps --all --quiet database-backup)"
BACKUP_EXISTING_NAME_MATCHES="$(docker container ls -a --format '{{.Names}}' | awk -v expected="${DESIRE_DATABASE_SOURCE_PROJECT}-database-backup-1" '$0 == expected { print }')"
test -z "$BACKUP_EXISTING_COMPOSE_IDS"
test -z "$BACKUP_EXISTING_NAME_MATCHES"

original_umask="$(umask)"
umask 077
# BEGIN CURRENT_HEAD_BACKUP_PARENT_CHAIN
for backup_parent_path in \
  "$DESIRE_DATABASE_BACKUP_PARENT" \
  "$DESIRE_DATABASE_BACKUP_SANDBOX_PARENT"
do
  if [ -e "$backup_parent_path" ] || [ -L "$backup_parent_path" ]; then
    test -d "$backup_parent_path"
    test ! -L "$backup_parent_path"
  else
    mkdir -m 0700 -- "$backup_parent_path"
  fi
  test -d "$backup_parent_path"
  test ! -L "$backup_parent_path"
  test "$(stat -f '%Lp|%u|%g' "$backup_parent_path")" = "700|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID"
done
# END CURRENT_HEAD_BACKUP_PARENT_CHAIN
test ! -e "$DESIRE_DATABASE_BACKUP_DIR"
test ! -L "$DESIRE_DATABASE_BACKUP_DIR"
mkdir -m 0700 -- "$DESIRE_DATABASE_BACKUP_DIR"
test -d "$DESIRE_DATABASE_BACKUP_DIR"
test ! -L "$DESIRE_DATABASE_BACKUP_DIR"
test "$(stat -f '%Lp|%u|%g' "$DESIRE_DATABASE_BACKUP_DIR")" = "700|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID"
umask "$original_umask"

compose_v13_backup up -d --no-deps --no-build --no-recreate database-backup
test "$(compose_v13_backup ps --all --quiet database-backup | wc -l | tr -d ' ')" = 1
BACKUP_CONTAINER_ID="$(compose_v13_backup ps --all --quiet database-backup)"
test -n "$BACKUP_CONTAINER_ID"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}' "$BACKUP_CONTAINER_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|database-backup"
test "$(docker inspect --format '{{with index .NetworkSettings.Networks "desire-supply-e2e-ten-account-v13_data"}}{{.NetworkID}}{{end}}' "$BACKUP_CONTAINER_ID")" = "$SOURCE_DATA_NETWORK_ID"
BACKUP_WAIT_STATUS="$(docker wait "$BACKUP_CONTAINER_ID")"
test "$BACKUP_WAIT_STATUS" = 0
test "$(docker inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$BACKUP_CONTAINER_ID")" = "exited|0|0"

BACKUP_LOG="$(compose_v13_backup logs --no-color --no-log-prefix database-backup)"
test "$BACKUP_LOG" = '{"artifact":"v13-iam37-profile3-demand10-trust7-taxonomy2-drill01","status":"DATABASE_BACKUP_READY"}'
BACKUP_READY_COUNT="$(printf '%s\n' "$BACKUP_LOG" | grep -Fo '"status":"DATABASE_BACKUP_READY"' | wc -l | tr -d ' ')"
test "$BACKUP_READY_COUNT" = 1
test "$(find "$DESIRE_DATABASE_BACKUP_DIR" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 3
for backup_artifact_name in \
  "$DESIRE_DATABASE_BACKUP_BASENAME.dump" \
  "$DESIRE_DATABASE_BACKUP_BASENAME.facts.json" \
  "$DESIRE_DATABASE_BACKUP_BASENAME.sha256"
do
  backup_artifact_path="$DESIRE_DATABASE_BACKUP_DIR/$backup_artifact_name"
  test -f "$backup_artifact_path"
  test ! -L "$backup_artifact_path"
  test -s "$backup_artifact_path"
  test "$(stat -f '%Lp|%u|%g|%l' "$backup_artifact_path")" = "600|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID|1"
done

test "$(compose_v13_backup ps --all --quiet db)" = "$SOURCE_DB_CONTAINER_ID"
test "$(compose_v13_backup ps --all --quiet api)" = "$SOURCE_API_CONTAINER_ID"
test "$(docker inspect --format '{{.State.StartedAt}}' "$SOURCE_DB_CONTAINER_ID")" = "$SOURCE_DB_STARTED_AT"
test "$(docker inspect --format '{{.RestartCount}}' "$SOURCE_DB_CONTAINER_ID")" = "$SOURCE_DB_RESTART_COUNT"
test "$(docker inspect --format '{{.Image}}' "$SOURCE_DB_CONTAINER_ID")" = "$SOURCE_DB_IMAGE_ID"
test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}' "$SOURCE_DB_CONTAINER_ID")" = "running|healthy"
test "$(docker inspect --format '{{.State.StartedAt}}' "$SOURCE_API_CONTAINER_ID")" = "$SOURCE_API_STARTED_AT"
test "$(docker inspect --format '{{.RestartCount}}' "$SOURCE_API_CONTAINER_ID")" = "$SOURCE_API_RESTART_COUNT"
test "$(docker inspect --format '{{.Image}}' "$SOURCE_API_CONTAINER_ID")" = "$SOURCE_API_IMAGE_ID"
test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "$SOURCE_API_CONTAINER_ID")" = "running|healthy|0"
test "$(docker image inspect --format '{{.Id}}' "desire-supply-platform:e2e-ten-account-v13-iam37-demand10-trust7")" = "$SOURCE_API_IMAGE_ID"
test "$(docker network inspect --format '{{.Id}}' "$SOURCE_DATA_NETWORK")" = "$SOURCE_DATA_NETWORK_ID"
test "$(docker inspect --format '{{with index .NetworkSettings.Networks "desire-supply-e2e-ten-account-v13_data"}}{{.NetworkID}}{{end}}' "$SOURCE_DB_CONTAINER_ID")" = "$SOURCE_DATA_NETWORK_ID"
test "$(docker volume inspect --format '{{.CreatedAt}}' "$SOURCE_DATA_VOLUME")" = "$SOURCE_DATA_VOLUME_CREATED_AT"
test "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}|{{.Name}}{{end}}{{end}}' "$SOURCE_DB_CONTAINER_ID")" = "volume|$SOURCE_DATA_VOLUME"
# END CURRENT_HEAD_V13_BACKUP
```

从任一 backup parent 创建或 leaf 目录创建开始，任何失败都会把这个 v13 source
项目、basename 和三份 artifact 永久锁定为证据；不得重试、`run --rm`、`down`、`rm`、
删除 partial artifact 或重新执行 `up`。下一次尝试必须获得新授权并使用新的版本化 source
project、backup 目录和 basename。只有上面所有 source identity、零 recreation、exit/restart、
日志、artifact 与 post-invariant 检查全部通过，才可进入下面的隔离恢复。

#### 4.8.2 当前头部隔离恢复与 replay

本标题同样是 verifier 冻结的历史 v13 标签，不是 current v27 操作入口；v26 也已是冻结历史。restore verification
network 固定为 `internal: true`，默认候选是
`${DESIRE_DATABASE_RESTORE_SUBNET:-172.16.232.0/24}`，不允许 gateway、Compose `name` 或
`external`。这个 `/24` 不是跨宿主机通用保证。每次 fresh drill 或网络环境变化后，必须先
枚举 daemon default-address-pools、全部 Docker CIDR、宿主直连路由和更具体路由；全隧道 VPN
连接前后都要检查。可在对应宿主系统执行以下只读预检；`netstat` 用于 macOS/BSD，`ip` 用于
Linux：

```bash
docker info --format '{{ json .DefaultAddressPools }}'
docker network ls -q | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}'
netstat -rn
ip -4 route show table all
```

确认候选与 Docker、LAN、VPN 及其他宿主路由均不重叠后，必须在同一 shell 执行下面的固定
v13 drill01 协议。不得替换为占位符、自动 IPAM、v9 drill01、v12 或任何失败/已有 project。
restore 复用并校验 source API 已经消费过 journey/restart 的 Platform image ID；不得再次 build、
重新标记或用相同 tag 指向另一 image：

```bash
# BEGIN CURRENT_HEAD_RESTORE_PREFLIGHT
set -eu
set -o pipefail
test "$(pwd -P)" = "/Users/shiyaozhang/Developer/desire-supply"
test -z "${COMPOSE_PROJECT_NAME+x}"
test -z "${COMPOSE_COMPATIBILITY+x}"
test -z "${DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE+x}"
test -z "${DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE+x}"
test -z "${DESIRE_IDENTITY_SOURCE_DIR+x}"
test -z "${DESIRE_INTERNAL_SANDBOX_TLS_DIR+x}"
test -z "${DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR+x}"
export DESIRE_DATABASE_SOURCE_PROJECT="desire-supply-e2e-ten-account-v13"
export DESIRE_DATABASE_RESTORE_PROJECT="desire-restore-verify-v13drill01"
export DESIRE_DATABASE_BACKUP_DIR="/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v13drill01"
export DESIRE_DATABASE_BACKUP_BASENAME="v13-iam37-profile3-demand10-trust7-taxonomy2-drill01"
export DESIRE_DB_PASSWORD_FILE="/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/db_superuser_password.txt"
export DESIRE_IMAGE_TAG="e2e-ten-account-v13-iam37-demand10-trust7"
export DESIRE_DATABASE_RESTORE_SUBNET="172.16.232.0/24"
DESIRE_DATABASE_OPERATIONS_UID="$(id -u)"
DESIRE_DATABASE_OPERATIONS_GID="$(id -g)"
export DESIRE_DATABASE_OPERATIONS_UID DESIRE_DATABASE_OPERATIONS_GID

test "$DESIRE_DATABASE_SOURCE_PROJECT" = "desire-supply-e2e-ten-account-v13"
test "$DESIRE_DATABASE_RESTORE_PROJECT" = "desire-restore-verify-v13drill01"
test "$DESIRE_DATABASE_BACKUP_DIR" = "/Users/shiyaozhang/Developer/desire-supply/backups/internal-sandbox/v13drill01"
test "$DESIRE_DATABASE_BACKUP_BASENAME" = "v13-iam37-profile3-demand10-trust7-taxonomy2-drill01"
test "$DESIRE_DB_PASSWORD_FILE" = "/Users/shiyaozhang/Developer/desire-supply/secrets/e2e-ten-account-v13/db_superuser_password.txt"
test "$DESIRE_IMAGE_TAG" = "e2e-ten-account-v13-iam37-demand10-trust7"
test "$DESIRE_DATABASE_RESTORE_SUBNET" = "172.16.232.0/24"

test -f "$DESIRE_DB_PASSWORD_FILE"
test ! -L "$DESIRE_DB_PASSWORD_FILE"
test -s "$DESIRE_DB_PASSWORD_FILE"
test "$(stat -f '%Lp|%u|%g|%l' "$DESIRE_DB_PASSWORD_FILE")" = "600|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID|1"
test -d "$DESIRE_DATABASE_BACKUP_DIR"
test ! -L "$DESIRE_DATABASE_BACKUP_DIR"
test "$(stat -f '%Lp|%u|%g' "$DESIRE_DATABASE_BACKUP_DIR")" = "700|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID"
test "$(find "$DESIRE_DATABASE_BACKUP_DIR" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 3
for restore_artifact_name in \
  "$DESIRE_DATABASE_BACKUP_BASENAME.dump" \
  "$DESIRE_DATABASE_BACKUP_BASENAME.facts.json" \
  "$DESIRE_DATABASE_BACKUP_BASENAME.sha256"
do
  restore_artifact_path="$DESIRE_DATABASE_BACKUP_DIR/$restore_artifact_name"
  test -f "$restore_artifact_path"
  test ! -L "$restore_artifact_path"
  test -s "$restore_artifact_path"
  test "$(stat -f '%Lp|%u|%g|%l' "$restore_artifact_path")" = "600|$DESIRE_DATABASE_OPERATIONS_UID|$DESIRE_DATABASE_OPERATIONS_GID|1"
done

DESIRE_DATABASE_RESTORE_DUMP_PATH="$DESIRE_DATABASE_BACKUP_DIR/$DESIRE_DATABASE_BACKUP_BASENAME.dump"
DESIRE_DATABASE_RESTORE_FACTS_PATH="$DESIRE_DATABASE_BACKUP_DIR/$DESIRE_DATABASE_BACKUP_BASENAME.facts.json"
DESIRE_DATABASE_RESTORE_MANIFEST_PATH="$DESIRE_DATABASE_BACKUP_DIR/$DESIRE_DATABASE_BACKUP_BASENAME.sha256"
DESIRE_DATABASE_RESTORE_DUMP_STAT="$(stat -f '%Lp|%u|%g|%z|%m|%c|%i|%l' "$DESIRE_DATABASE_RESTORE_DUMP_PATH")"
DESIRE_DATABASE_RESTORE_FACTS_STAT="$(stat -f '%Lp|%u|%g|%z|%m|%c|%i|%l' "$DESIRE_DATABASE_RESTORE_FACTS_PATH")"
DESIRE_DATABASE_RESTORE_MANIFEST_STAT="$(stat -f '%Lp|%u|%g|%z|%m|%c|%i|%l' "$DESIRE_DATABASE_RESTORE_MANIFEST_PATH")"
DESIRE_DATABASE_RESTORE_DUMP_SHA256="$(shasum -a 256 "$DESIRE_DATABASE_RESTORE_DUMP_PATH" | awk '{print $1}')"
DESIRE_DATABASE_RESTORE_FACTS_SHA256="$(shasum -a 256 "$DESIRE_DATABASE_RESTORE_FACTS_PATH" | awk '{print $1}')"
DESIRE_DATABASE_RESTORE_MANIFEST_SHA256="$(shasum -a 256 "$DESIRE_DATABASE_RESTORE_MANIFEST_PATH" | awk '{print $1}')"
test -n "$DESIRE_DATABASE_RESTORE_DUMP_STAT"
test -n "$DESIRE_DATABASE_RESTORE_FACTS_STAT"
test -n "$DESIRE_DATABASE_RESTORE_MANIFEST_STAT"
test -n "$DESIRE_DATABASE_RESTORE_DUMP_SHA256"
test -n "$DESIRE_DATABASE_RESTORE_FACTS_SHA256"
test -n "$DESIRE_DATABASE_RESTORE_MANIFEST_SHA256"

compose_v13_restore_source() {
  docker compose \
    --project-name "$DESIRE_DATABASE_SOURCE_PROJECT" \
    --env-file "$PWD/secrets/e2e-ten-account-v13/compose.env" \
    -f "$PWD/compose.yaml" \
    -f "$PWD/secrets/e2e-ten-account-v13/compose.ipam.yaml" "$@"
}

compose_v13_restore() {
  docker compose \
    --project-name "$DESIRE_DATABASE_RESTORE_PROJECT" \
    -f "$PWD/compose.yaml" \
    -f "$PWD/deploy/postgres-operations.compose.yaml" \
    --profile database-restore-verify "$@"
}

compose_v13_restore_source config --quiet
compose_v13_restore config --quiet
test "$(compose_v13_restore_source ps --all --quiet db | wc -l | tr -d ' ')" = 1
test "$(compose_v13_restore_source ps --all --quiet api | wc -l | tr -d ' ')" = 1
DESIRE_DATABASE_RESTORE_SOURCE_DB_ID="$(compose_v13_restore_source ps --all --quiet db)"
DESIRE_DATABASE_RESTORE_SOURCE_API_ID="$(compose_v13_restore_source ps --all --quiet api)"
test -n "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID"
test -n "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|db"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|api"
test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "running|healthy|0"
test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "running|healthy|0"
DESIRE_DATABASE_RESTORE_SOURCE_DB_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")"
DESIRE_DATABASE_RESTORE_SOURCE_DB_RESTART_COUNT="$(docker inspect --format '{{.RestartCount}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")"
DESIRE_DATABASE_RESTORE_SOURCE_API_STARTED_AT="$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")"
DESIRE_DATABASE_RESTORE_SOURCE_API_RESTART_COUNT="$(docker inspect --format '{{.RestartCount}}' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")"
DESIRE_DATABASE_RESTORE_SOURCE_DB_IMAGE_ID="$(docker inspect --format '{{.Image}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")"
DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID="$(docker inspect --format '{{.Image}}' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")"
DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_TAG_ID="$(docker image inspect --format '{{.Id}}' "desire-supply-platform:$DESIRE_IMAGE_TAG")"
test -n "$DESIRE_DATABASE_RESTORE_SOURCE_DB_STARTED_AT"
test -n "$DESIRE_DATABASE_RESTORE_SOURCE_API_STARTED_AT"
test -n "$DESIRE_DATABASE_RESTORE_SOURCE_DB_IMAGE_ID"
test -n "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"
test "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_TAG_ID" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"
DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK="${DESIRE_DATABASE_SOURCE_PROJECT}_data"
DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME="${DESIRE_DATABASE_SOURCE_PROJECT}_postgres-data"
DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID="$(docker network inspect --format '{{.Id}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK")"
DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME_CREATED_AT="$(docker volume inspect --format '{{.CreatedAt}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME")"
test -n "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID"
test -n "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME_CREATED_AT"
test "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID" = "$SOURCE_DB_CONTAINER_ID"
test "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID" = "$DESIRE_E2E_DB_ID"
test "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID" = "$SOURCE_API_CONTAINER_ID"
test "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID" = "$DESIRE_E2E_API_ID"
test "$DESIRE_DATABASE_RESTORE_SOURCE_DB_STARTED_AT" = "$SOURCE_DB_STARTED_AT"
test "$DESIRE_DATABASE_RESTORE_SOURCE_DB_STARTED_AT" = "$DESIRE_E2E_DB_STARTED_AT"
test "$DESIRE_DATABASE_RESTORE_SOURCE_DB_RESTART_COUNT" = "$SOURCE_DB_RESTART_COUNT"
test "$DESIRE_DATABASE_RESTORE_SOURCE_API_STARTED_AT" = "$SOURCE_API_STARTED_AT"
test "$DESIRE_DATABASE_RESTORE_SOURCE_API_STARTED_AT" = "$DESIRE_E2E_API_STARTED_AT"
test "$DESIRE_DATABASE_RESTORE_SOURCE_API_RESTART_COUNT" = "$SOURCE_API_RESTART_COUNT"
test "$DESIRE_DATABASE_RESTORE_SOURCE_DB_IMAGE_ID" = "$SOURCE_DB_IMAGE_ID"
test "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID" = "$SOURCE_API_IMAGE_ID"
test "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID" = "$DESIRE_E2E_PLATFORM_IMAGE_ID"
test "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID" = "$SOURCE_DATA_NETWORK_ID"
test "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID" = "$DESIRE_E2E_DATA_NETWORK_ID"
test "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME_CREATED_AT" = "$SOURCE_DATA_VOLUME_CREATED_AT"
test "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME_CREATED_AT" = "$DESIRE_E2E_DATA_VOLUME_CREATED_AT"
test "$(docker network inspect --format '{{ index .Labels "com.docker.compose.project" }}|{{ index .Labels "com.docker.compose.network" }}' "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK")" = "$DESIRE_DATABASE_SOURCE_PROJECT|data"
test "$(docker volume inspect --format '{{ index .Labels "com.docker.compose.project" }}|{{ index .Labels "com.docker.compose.volume" }}' "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME")" = "$DESIRE_DATABASE_SOURCE_PROJECT|postgres-data"
test "$(docker inspect --format '{{with index .NetworkSettings.Networks "desire-supply-e2e-ten-account-v13_data"}}{{.NetworkID}}{{end}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID"
test "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}|{{.Name}}{{end}}{{end}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "volume|$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME"

DESIRE_DATABASE_RESTORE_CONTAINER_PREFIX="${DESIRE_DATABASE_RESTORE_PROJECT}-"
DESIRE_DATABASE_RESTORE_RESOURCE_PREFIX="${DESIRE_DATABASE_RESTORE_PROJECT}_"
DESIRE_DATABASE_RESTORE_COMPOSE_CONTAINER_IDS="$(compose_v13_restore ps --all --quiet)"
DESIRE_DATABASE_RESTORE_PROJECT_CONTAINER_IDS="$(docker container ls -aq --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT")"
DESIRE_DATABASE_RESTORE_PROJECT_NETWORK_IDS="$(docker network ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT")"
DESIRE_DATABASE_RESTORE_PROJECT_VOLUME_IDS="$(docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT")"
DESIRE_DATABASE_RESTORE_ALL_CONTAINER_NAMES="$(docker container ls -a --format '{{.Names}}')"
DESIRE_DATABASE_RESTORE_ALL_NETWORK_NAMES="$(docker network ls --format '{{.Name}}')"
DESIRE_DATABASE_RESTORE_ALL_VOLUME_NAMES="$(docker volume ls --format '{{.Name}}')"
DESIRE_DATABASE_RESTORE_CONTAINER_PREFIX_MATCHES="$(printf '%s\n' "$DESIRE_DATABASE_RESTORE_ALL_CONTAINER_NAMES" | awk -v prefix="$DESIRE_DATABASE_RESTORE_CONTAINER_PREFIX" 'index($0, prefix) == 1 { print }')"
DESIRE_DATABASE_RESTORE_NETWORK_PREFIX_MATCHES="$(printf '%s\n' "$DESIRE_DATABASE_RESTORE_ALL_NETWORK_NAMES" | awk -v prefix="$DESIRE_DATABASE_RESTORE_RESOURCE_PREFIX" 'index($0, prefix) == 1 { print }')"
DESIRE_DATABASE_RESTORE_VOLUME_PREFIX_MATCHES="$(printf '%s\n' "$DESIRE_DATABASE_RESTORE_ALL_VOLUME_NAMES" | awk -v prefix="$DESIRE_DATABASE_RESTORE_RESOURCE_PREFIX" 'index($0, prefix) == 1 { print }')"
test -z "$DESIRE_DATABASE_RESTORE_COMPOSE_CONTAINER_IDS"
test -z "$DESIRE_DATABASE_RESTORE_PROJECT_CONTAINER_IDS"
test -z "$DESIRE_DATABASE_RESTORE_PROJECT_NETWORK_IDS"
test -z "$DESIRE_DATABASE_RESTORE_PROJECT_VOLUME_IDS"
test -z "$DESIRE_DATABASE_RESTORE_CONTAINER_PREFIX_MATCHES"
test -z "$DESIRE_DATABASE_RESTORE_NETWORK_PREFIX_MATCHES"
test -z "$DESIRE_DATABASE_RESTORE_VOLUME_PREFIX_MATCHES"

DESIRE_DATABASE_RESTORE_EXPECTED_BOOTSTRAP='{"catalogs":{"demand":{"applied_versions":[1,2,3,4,5,6,7,8,9,10],"skipped_versions":[]},"iam":{"applied_versions":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37],"skipped_versions":[]},"profile":{"applied_versions":[1,2,3],"skipped_versions":[]},"taxonomy":{"applied_versions":[1,2],"skipped_versions":[]},"trust":{"applied_versions":[1,2,3,4,5,6,7],"skipped_versions":[]}},"status":"SCHEMA_READY"}'
DESIRE_DATABASE_RESTORE_EXPECTED_VERIFY='{"artifact":"v13-iam37-profile3-demand10-trust7-taxonomy2-drill01","status":"DATABASE_RESTORE_VERIFIED"}'
DESIRE_DATABASE_RESTORE_EXPECTED_REPLAY='{"catalogs":{"demand":{"applied_versions":[],"skipped_versions":[1,2,3,4,5,6,7,8,9,10]},"iam":{"applied_versions":[],"skipped_versions":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37]},"profile":{"applied_versions":[],"skipped_versions":[1,2,3]},"taxonomy":{"applied_versions":[],"skipped_versions":[1,2]},"trust":{"applied_versions":[],"skipped_versions":[1,2,3,4,5,6,7]}},"status":"SCHEMA_READY"}'
# END CURRENT_HEAD_RESTORE_PREFLIGHT
```

上述 preflight 必须在同一 shell fail-closed：retained artifact 要再次证明为当前 UID/GID 所有的
0700 真实 leaf 和三份 0600 regular non-symlink 文件，并在启动前记录每份 artifact 的完整 stat
与 SHA-256；source DB/API、data network、`postgres-data` volume 和 source API image/tag 也必须
锁定。fresh project namespace 既要按 project label 断言为空，也要按 container 的
`${DESIRE_DATABASE_RESTORE_PROJECT}-` 与 network/volume 的
`${DESIRE_DATABASE_RESTORE_PROJECT}_` name prefix 断言为空，不能把裸枚举输出当作 absence 证据。
唯一 restore 启动命令必须以最终 `database-restore-replay` 为 target，并明确禁止 build：

```bash
# BEGIN CURRENT_HEAD_RESTORE_EXECUTION
test "$(docker image inspect --format '{{.Id}}' "desire-supply-platform:$DESIRE_IMAGE_TAG")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"
compose_v13_restore up -d --no-build --no-recreate database-restore-replay
DESIRE_DATABASE_RESTORE_REPLAY_ID="$(compose_v13_restore ps --all --quiet database-restore-replay)"
test -n "$DESIRE_DATABASE_RESTORE_REPLAY_ID"
test "$(docker wait "$DESIRE_DATABASE_RESTORE_REPLAY_ID")" = "0"
# END CURRENT_HEAD_RESTORE_EXECUTION
```

退出码 0 后必须运行完整 post-run gate；不能只看最终 service 或人工浏览日志：

```bash
# BEGIN CURRENT_HEAD_RESTORE_POSTRUN
test "$(compose_v13_restore ps --all --quiet | wc -l | tr -d '[:space:]')" = "4"
test "$(docker container ls -aq --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d '[:space:]')" = "4"
test "$(docker network ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d '[:space:]')" = "1"
test "$(docker volume ls -q --filter "label=com.docker.compose.project=$DESIRE_DATABASE_RESTORE_PROJECT" | wc -l | tr -d '[:space:]')" = "1"

DESIRE_DATABASE_RESTORE_TARGET_ID="$(compose_v13_restore ps --all --quiet database-restore-target)"
DESIRE_DATABASE_RESTORE_BOOTSTRAP_ID="$(compose_v13_restore ps --all --quiet database-restore-bootstrap)"
DESIRE_DATABASE_RESTORE_VERIFY_ID="$(compose_v13_restore ps --all --quiet database-restore-verify)"
test -n "$DESIRE_DATABASE_RESTORE_TARGET_ID"
test -n "$DESIRE_DATABASE_RESTORE_BOOTSTRAP_ID"
test -n "$DESIRE_DATABASE_RESTORE_VERIFY_ID"
test -n "$DESIRE_DATABASE_RESTORE_REPLAY_ID"
test "$(docker inspect --format '{{.Name}}' "$DESIRE_DATABASE_RESTORE_TARGET_ID")" = "/${DESIRE_DATABASE_RESTORE_PROJECT}-database-restore-target-1"
test "$(docker inspect --format '{{.Name}}' "$DESIRE_DATABASE_RESTORE_BOOTSTRAP_ID")" = "/${DESIRE_DATABASE_RESTORE_PROJECT}-database-restore-bootstrap-1"
test "$(docker inspect --format '{{.Name}}' "$DESIRE_DATABASE_RESTORE_VERIFY_ID")" = "/${DESIRE_DATABASE_RESTORE_PROJECT}-database-restore-verify-1"
test "$(docker inspect --format '{{.Name}}' "$DESIRE_DATABASE_RESTORE_REPLAY_ID")" = "/${DESIRE_DATABASE_RESTORE_PROJECT}-database-restore-replay-1"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}' "$DESIRE_DATABASE_RESTORE_TARGET_ID")" = "$DESIRE_DATABASE_RESTORE_PROJECT|database-restore-target"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}' "$DESIRE_DATABASE_RESTORE_BOOTSTRAP_ID")" = "$DESIRE_DATABASE_RESTORE_PROJECT|database-restore-bootstrap"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}' "$DESIRE_DATABASE_RESTORE_VERIFY_ID")" = "$DESIRE_DATABASE_RESTORE_PROJECT|database-restore-verify"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}' "$DESIRE_DATABASE_RESTORE_REPLAY_ID")" = "$DESIRE_DATABASE_RESTORE_PROJECT|database-restore-replay"
test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "$DESIRE_DATABASE_RESTORE_TARGET_ID")" = "running|healthy|0"
test "$(docker inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_DATABASE_RESTORE_BOOTSTRAP_ID")" = "exited|0|0"
test "$(docker inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_DATABASE_RESTORE_VERIFY_ID")" = "exited|0|0"
test "$(docker inspect --format '{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}' "$DESIRE_DATABASE_RESTORE_REPLAY_ID")" = "exited|0|0"
test "$(docker inspect --format '{{.Image}}' "$DESIRE_DATABASE_RESTORE_BOOTSTRAP_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"
test "$(docker inspect --format '{{.Image}}' "$DESIRE_DATABASE_RESTORE_REPLAY_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"
DESIRE_DATABASE_RESTORE_POSTGRES_IMAGE_ID="$(docker inspect --format '{{.Image}}' "$DESIRE_DATABASE_RESTORE_TARGET_ID")"
test -n "$DESIRE_DATABASE_RESTORE_POSTGRES_IMAGE_ID"
test "$(docker inspect --format '{{.Image}}' "$DESIRE_DATABASE_RESTORE_VERIFY_ID")" = "$DESIRE_DATABASE_RESTORE_POSTGRES_IMAGE_ID"

DESIRE_DATABASE_RESTORE_NETWORK="${DESIRE_DATABASE_RESTORE_PROJECT}_database-restore-verification"
DESIRE_DATABASE_RESTORE_VOLUME="${DESIRE_DATABASE_RESTORE_PROJECT}_postgres-restore-verification-data"
DESIRE_DATABASE_RESTORE_NETWORK_ID="$(docker network inspect --format '{{.Id}}' "$DESIRE_DATABASE_RESTORE_NETWORK")"
DESIRE_DATABASE_RESTORE_VOLUME_CREATED_AT="$(docker volume inspect --format '{{.CreatedAt}}' "$DESIRE_DATABASE_RESTORE_VOLUME")"
test -n "$DESIRE_DATABASE_RESTORE_NETWORK_ID"
test -n "$DESIRE_DATABASE_RESTORE_VOLUME_CREATED_AT"
test "$(docker network inspect --format '{{ index .Labels "com.docker.compose.project" }}|{{ index .Labels "com.docker.compose.network" }}' "$DESIRE_DATABASE_RESTORE_NETWORK")" = "$DESIRE_DATABASE_RESTORE_PROJECT|database-restore-verification"
test "$(docker network inspect --format '{{.Internal}}|{{len .IPAM.Config}}|{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$DESIRE_DATABASE_RESTORE_NETWORK")" = "true|1|$DESIRE_DATABASE_RESTORE_SUBNET"
test "$(docker volume inspect --format '{{ index .Labels "com.docker.compose.project" }}|{{ index .Labels "com.docker.compose.volume" }}' "$DESIRE_DATABASE_RESTORE_VOLUME")" = "$DESIRE_DATABASE_RESTORE_PROJECT|postgres-restore-verification-data"
test "$(docker inspect --format '{{with index .NetworkSettings.Networks "desire-restore-verify-v13drill01_database-restore-verification"}}{{.NetworkID}}{{end}}' "$DESIRE_DATABASE_RESTORE_TARGET_ID")" = "$DESIRE_DATABASE_RESTORE_NETWORK_ID"
test "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}|{{.Name}}{{end}}{{end}}' "$DESIRE_DATABASE_RESTORE_TARGET_ID")" = "volume|$DESIRE_DATABASE_RESTORE_VOLUME"

DESIRE_DATABASE_RESTORE_BOOTSTRAP_LOG="$(compose_v13_restore logs --no-color --no-log-prefix database-restore-bootstrap)"
DESIRE_DATABASE_RESTORE_VERIFY_LOG="$(compose_v13_restore logs --no-color --no-log-prefix database-restore-verify)"
DESIRE_DATABASE_RESTORE_REPLAY_LOG="$(compose_v13_restore logs --no-color --no-log-prefix database-restore-replay)"
test "$DESIRE_DATABASE_RESTORE_BOOTSTRAP_LOG" = "$DESIRE_DATABASE_RESTORE_EXPECTED_BOOTSTRAP"
test "$DESIRE_DATABASE_RESTORE_VERIFY_LOG" = "$DESIRE_DATABASE_RESTORE_EXPECTED_VERIFY"
test "$DESIRE_DATABASE_RESTORE_REPLAY_LOG" = "$DESIRE_DATABASE_RESTORE_EXPECTED_REPLAY"

test "$(find "$DESIRE_DATABASE_BACKUP_DIR" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = "3"
test "$(stat -f '%Lp|%u|%g|%z|%m|%c|%i|%l' "$DESIRE_DATABASE_RESTORE_DUMP_PATH")" = "$DESIRE_DATABASE_RESTORE_DUMP_STAT"
test "$(stat -f '%Lp|%u|%g|%z|%m|%c|%i|%l' "$DESIRE_DATABASE_RESTORE_FACTS_PATH")" = "$DESIRE_DATABASE_RESTORE_FACTS_STAT"
test "$(stat -f '%Lp|%u|%g|%z|%m|%c|%i|%l' "$DESIRE_DATABASE_RESTORE_MANIFEST_PATH")" = "$DESIRE_DATABASE_RESTORE_MANIFEST_STAT"
test "$(shasum -a 256 "$DESIRE_DATABASE_RESTORE_DUMP_PATH" | awk '{print $1}')" = "$DESIRE_DATABASE_RESTORE_DUMP_SHA256"
test "$(shasum -a 256 "$DESIRE_DATABASE_RESTORE_FACTS_PATH" | awk '{print $1}')" = "$DESIRE_DATABASE_RESTORE_FACTS_SHA256"
test "$(shasum -a 256 "$DESIRE_DATABASE_RESTORE_MANIFEST_PATH" | awk '{print $1}')" = "$DESIRE_DATABASE_RESTORE_MANIFEST_SHA256"

test "$(compose_v13_restore_source ps --all --quiet db)" = "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID"
test "$(compose_v13_restore_source ps --all --quiet api)" = "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|db"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_SOURCE_PROJECT|api"
test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "running|healthy|0"
test "$(docker inspect --format '{{.State.Status}}|{{.State.Health.Status}}|{{.RestartCount}}' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "running|healthy|0"
test "$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DB_STARTED_AT"
test "$(docker inspect --format '{{.RestartCount}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DB_RESTART_COUNT"
test "$(docker inspect --format '{{.State.StartedAt}}' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_API_STARTED_AT"
test "$(docker inspect --format '{{.RestartCount}}' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_API_RESTART_COUNT"
test "$(docker inspect --format '{{.Image}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DB_IMAGE_ID"
test "$(docker inspect --format '{{.Image}}' "$DESIRE_DATABASE_RESTORE_SOURCE_API_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"
test "$(docker image inspect --format '{{.Id}}' "desire-supply-platform:$DESIRE_IMAGE_TAG")" = "$DESIRE_DATABASE_RESTORE_SOURCE_PLATFORM_IMAGE_ID"
test "$(docker network inspect --format '{{.Id}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID"
test "$(docker volume inspect --format '{{.CreatedAt}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME_CREATED_AT"
test "$(docker inspect --format '{{with index .NetworkSettings.Networks "desire-supply-e2e-ten-account-v13_data"}}{{.NetworkID}}{{end}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "$DESIRE_DATABASE_RESTORE_SOURCE_DATA_NETWORK_ID"
test "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}|{{.Name}}{{end}}{{end}}' "$DESIRE_DATABASE_RESTORE_SOURCE_DB_ID")" = "volume|$DESIRE_DATABASE_RESTORE_SOURCE_DATA_VOLUME"
# END CURRENT_HEAD_RESTORE_POSTRUN
```

只有四个固定 container、一个 internal `172.16.232.0/24` network、一个 restore volume、三份
精确日志、三份未变 artifact，以及 source DB/API/network/volume/image 全部通过，才构成 v13
restore/replay 证据。若出现任何额外/缺失资源、额外 applied version、缺少 exact skip、
`BLOCKED`、非零退出或 source/artifact 漂移，必须保留 project 原状并停止，不得重跑或清理。
<!-- BEGIN CURRENT_HEAD_RESTORE_OFFSITE_AUTHORITY -->
本机 drill 的 custom dump、facts JSON 和 manifest 仍是明文 artifact；`.sha256` 只是未签名 SHA-256
完整性记录，不是加密、签名或 MAC。在获得明确的
`recipient/KMS/tool/destination authority` 前，不得实现或宣称 encrypted/offsite backup；
加密离机备份仍等待有权操作者明确指定 recipient、KMS、tool 与 destination。
<!-- END CURRENT_HEAD_RESTORE_OFFSITE_AUTHORITY -->

2026-08-19 已完成一次 v9 逻辑 backup → fresh isolated-volume restore 动态演练。工具固定
PG18/IAM36/Profile3/Demand9/Trust5/Taxonomy2，并校验五域 reviewed contract digest、非空单行
core facts、archive 与双 checksum。备份容器属于独立 project，仅通过 v9 internal data network
做协议级读取，没有挂载 v9 PostgreSQL volume；v9 DB 全程保持 healthy、restart 0。

演练 project 为 `desire-restore-verify-v9drill01`，artifact basename 为
`v9-iam36-profile3-demand9-trust5-taxonomy2-drill01`。备份精确返回
`DATABASE_BACKUP_READY`；全新内部网络与全新 volume 上的恢复精确返回
`DATABASE_RESTORE_VERIFIED`。恢复后 IAM `0..36`、Profile `1..3`、Demand `1..9`、Trust
`1..5`、Taxonomy `1..2` 全部 exact skip；Demand/Trust/Appeal receipt、audit、outbox 与核心
终态的去标识聚合和源库一致。该 project、容器、network、volume 与三份 0600 artifact 均保留，
禁止用同一 drill/basename 重跑或清理。

这项只证明本机逻辑备份与隔离恢复。上述受控离机保护、定期演练、PITR 与告警仍未完成；任何资源
清理都需要另行精确确认目标，本手册不提供删除命令。

## 5. Dev Container

1. 先完成第 4.1、4.2 节；
2. 在 VS Code 打开仓库根目录；
3. 执行 **Dev Containers: Reopen in Container**；
4. 等待最后显示 `{"status":"DEVCONTAINER_DEPENDENCIES_READY"}`；
5. 在容器终端执行：

```bash
/usr/local/bin/desire-devcontainer-toolchain-check
python3 --version
uv --version
node --version
psql --version
cd /workspace/platform
uv run --offline --locked --extra test --extra server \
  python -m unittest discover -s tests -t . -v
cd /workspace/web
npm test
```

工具链门禁要求当前用户仍为 `node` 且不是 root，并验证 `/home/node` 与五个依赖 named-volume
root 均存在且可写。镜像构建期初始 UID 固定为 1000；运行期允许 Dev Containers 为 Linux
宿主映射成 1001 等非 root UID，不能把合法映射误判为工具链漂移。

Dev Container 不挂载 Docker socket，也不会自动启动 API/Web。完整说明见
[Dev Container 开发指南](/development/dev-container.md)。

## 6. 暂时不要运行的入口

- 不要在 identity bootstrap 或 API readiness 尚未成功时单独启动 `web/`，也不要把
  下游 `AUTH_BACKEND_UNAVAILABLE` 当成可以绕过初始化链的普通页面错误。
- 不要给 Docker API 使用 PostgreSQL superuser 作为在线身份。
- 不要 raw insert `ACTIVE` IAM User、Taxonomy、Profile marker 或业务事实。
- 不要用真实邮箱、OIDC subject、姓名、合同、文件或金额测试。
- 不要绑定 `0.0.0.0` 暴露本地合成 API，也不要通过 tunnel、Sites 或其他托管服务
  发布。
- 不要把 Caddy data 目录或 CA signing key 挂给 API；API 只能读取
  `root-ca.pem`，edge 只能读取 leaf chain/key。不要绕过浏览器 TLS 警告。
- 不要运行 `npm audit fix --force`。当前 Web 锁文件已在干净 `npm ci` 后达到 0 个已知
  漏洞，并由 CI 的 `npm audit --audit-level=high` 阻止高风险回归；后续升级仍须逐项做
  build、typecheck、lint 与 acceptance tests。

## 7. 最终通过清单

### 当前应能勾选

- [ ] Demo build、17 个测试、lint、typecheck 全绿；
- [ ] 五个制度场景可操作且边界文案持续可见；
- [ ] local_synthetic 11 个测试全绿；
- [ ] health 为 LIVE/READY，personas 精确为七个；
- [ ] Creator Consent 推进 revision，越权与 stale revision 被拒绝；
- [ ] 同一 SQLite 重启后进度仍在；
- [x] 容器静态契约通过；
- [x] v12 十账号动态验收确认没有使用真实资料、真实资金、外部副作用、公网暴露或 OpenAI Sites 发布。

### 服务器工作台动态证据与剩余放行项

- [x] 当前源码/运维工具的 v27 静态模式头保持 IAM head `0046`、Profile head `0005`、Demand head
  `0015`、Trust head `0022`、Matching head `0003`、Taxonomy head `0002`；v27 为
  `STATIC VERIFIED / NOT PRODUCTION EXECUTED`，历史 v25/v24 本地合成动态证据与 v23/v22 历史证据
  均单独记账；
- [x] IAM0024 session-security 13/13 历史回归切片保持 GREEN；它不是最终 schema head；
- [x] IAM `0031` Finance authority、IAM `0032` account-admin hardening、IAM `0033` 第七账号
  bootstrap、IAM `0034` ORG_ADMIN management 与 IAM `0035` invitation acceptance hardening
  属于历史增量证据；当前源码 head 已前移至 IAM0043，v12 动态结果仍只到 IAM0036；
- [x] 合成 OIDC 的 TLS/CA/双 hostname 已接入 Compose 且静态契约 GREEN；
- [x] v9/Trust5 GREEN 只作历史；v10 唯一 journey 失败，v11 restart 因重跑 one-shot 无效；
  v5、旧六账号 IAM32/Demand6 与更早结果同样只作追溯，且都不记作浏览器视觉 QA；
- [x] v12 fresh PostgreSQL 第一轮精确 apply IAM `0..36`、Profile `1..3`、Demand `1..9`、
  Trust `1..6`、Taxonomy `1..2`，第二轮 applied 全空并 exact skip 同一版本集合；
- [x] v12 taxonomy seed、11 个 online credentials 与 identity bootstrap 按序 GREEN；最终五个
  one-shot JSON 日志条数精确保持 `2/1/1/1/1`；
- [x] v12 project 的完整 Docker API 从容器内部返回 200 `READY`，Web/OIDC/Edge healthy，且 API 无
  host port/admin secret；
- [x] Taxonomy workload/consumer 授权与 Profile marker 已能通过正式离线命令生成；
- [x] 当前 API 挂载 15 个 role-bound DB credential 与 28 个 key carrier（43 份 material）；独立
  Matching runtime 挂载 5 个 role-bound credential 与 6 个 key carrier（11 份 material）；去重后的
  bundle 闭集为 19 个数据库 credential、34 个 key carrier，共 53 份 runtime material；
- [x] API 与 Matching runtime 的默认 dependency factory、server/runtime 入口、健康检查和精确
  config/secret mount 已闭合；
- [x] 共享 HTTP mux 已接入每请求一条、无 path/query/header/body/ID 的关闭低基数 telemetry；所有
  resolved Compose service 固定 `local`/`10m`/`3`/compress 的新容器日志合同；二者都不是 Audit、
  集中采集、告警或备份；
- [x] Trust1..6 冻结业务合同已把 Trust officer 读取收敛为 assignment discovery +
  assigned-case/assigned-hold 精确读取；hold-release 不再复用泛 case 读取路径；
- [x] Web ACCESS_ADMIN 闭合契约、OCC/CSRF/idempotency 与未知结果恢复的自动测试已通过；
- [x] 当前 `desire-supply-e2e-ten-account-v12` 数据卷的唯一旅程精确返回
  `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，覆盖十账号/八职责及 Trust/Appeal 闭环；
- [x] v12 五个持久服务完整 stop/recover 两轮；恢复只使用
  `up -d --no-deps --no-recreate --wait`，两轮均精确返回
  `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN` 且未重跑 one-shot；
- [x] v12 tag 的目标机 loopback TLS/OIDC 双 hostname 动态协议验收完成；
- [x] 2026-08-25 当时 checkout 的本地试用管理器完成
  `stop → STOPPED → resume → HEALTHY → stop → STOPPED`；没有重建容器、重跑 one-shot 或删除资源，
  restart verifier GREEN，PostgreSQL volume 和其余资源均保留；
- [x] 2026-08-26 当时 checkout 的全新栈完成 IAM41/Trust14 migration、十账号旅程与
  provider-only 邀请旅程；ACTIVE Creator 的第二权限接受已证明旧 authority 保留、User
  `N → N+1`、接受 `me` 与随后 `/v1/me` 完全一致；
- [x] 同一 2026-08-26 栈完成 `HEALTHY → STOPPED → resume → HEALTHY → STOPPED`，restart
  verifier GREEN，未重跑 one-shot，所有 Docker 资源和失败现场均保留；
- [ ] IAM42 上线前先停止并排空旧 API/worker，确认没有 live writer；随后让 migration composition
  自动执行真实存量 `public_name` 全量 preflight，按 NFC、精确 trim、1..160 Unicode code point、
  禁止 `Cc`/`Cf` 全部通过，并保持静默直至 IAM42 commit。本次 fresh 空卷只有零存量证据，不能替代
  服务器升级扫描；只读 preflight 与 migration 不是同一事务，不能宣称在线扫描具有原子性；
- [x] 历史 v21 的 IAM42/Demand11/Trust15 fresh migration、公开名称 exact replay/邀请 live join、provider-only 邀请和
  不重跑 one-shot 的 stop/resume/restart 已生成去标识本地动态证据；stale `412`、同名/角色/MFA
  负向边界由 HTTP/application/真实 PG18 回归覆盖；
- [x] 历史 v22 的 IAM42/Demand12/Trust16 fresh migration、十账号角色功能/临时 duty 配置与撤销、
  Finance 本人终态历史、provider-only 邀请以及不重跑 one-shot 的 stop/resume/restart 已 GREEN，
  并已冻结；它不是 v23/Trust17 动态证据；
- [x] 历史 v23 的 IAM42/Demand12/Trust17 fresh 本地栈从 `PREPARED` 到 `HEALTHY`，十账号与
  provider-only 旅程均 GREEN；`STOPPED -> resume -> HEALTHY` 后 restart GREEN，Trust 本人完成历史
  `discoverable=true` 且 `actor_scoped=true`，最终 `STOPPED`，十容器/四网络/一 PG volume/三应用镜像
  与四份 `0600` evidence JSON 全部保留，所有 `RestartCount=0`，未执行 down/delete/cleanup；
- [x] 历史冻结 v24 的 IAM42/Demand12/Trust18 fresh 本地栈从 `PREPARED` 到 `HEALTHY`，十账号与
  provider-only 旅程均 GREEN；Appeal Reviewer 本人 history/detail/completed task、错误角色/额外 query
  边界及第二 reviewer 的 actor 隔离均通过；`STOPPED -> resume -> HEALTHY` 后 restart GREEN，最终
  `STOPPED`，启动收据绑定的十容器、四网络、PG volume、应用镜像与私有 evidence 均保留，未执行
  down/delete/remove/`--rm`/prune；
- [x] 同一全新本地栈完成 IAM40/Trust13 migration 和十个 bootstrap 账号完整旅程；
- [x] provider-only invited Demand Owner 从 pending 无权限开始，经精确邀请接受后仅取得目标组织
  `DEMAND_OWNER`；管理入口保持 `404`，Demand create/replay/cancel/history 全部 GREEN；
- [x] 数据库去标识聚合为 11 active、0 pending、11 external identity；邀请身份没有 user role 或
  platform duty；
- [x] Demand Owner 的 `FUNDED → CANCELLED` 与 Trust Officer 本人完成历史已完成历史定向应用内浏览器验收；
- [ ] current-head v27 的完整十账号桌面/移动浏览器视觉 QA 完成；历史 v25 与冻结 v24 动态尝试中
  应用内 Browser 的隔离 localhost 无法桥接宿主机 Docker loopback，临时 hosts 映射已逐字恢复，
  未安装 CA trust 或绕过证书；这些历史失败不能冒充 v27 视觉 QA，v23/v22 也未完成；
- [x] Trust6 对应的 fresh Docker migration、唯一 journey 与两轮 restart 动态证据已在 v12 生成；
- [x] current-head v27 已签入并静态闭合 `deploy/postgres-backup-restore-v27.sh`、
  `deploy/postgres-core-facts-v27.sql` 与双 config operations overlay；它固定
  IAM46/Profile5/Demand15/Trust22/Matching3/Taxonomy2 heads/contracts，把 Matching v1-v3 全部 27 张
  durable domain tables 纳入隐私安全 count 与空目标门禁，且不改写 v26/v25 或更早历史资产；
  该静态入口没有运行 Docker、没有创建 artifact，也不是恢复演练证据；
- [ ] IAM46/Profile5/Demand15/Trust22/Matching3/Taxonomy2 current-head v27 的逻辑
  backup/isolated restore 动态演练尚未生成；历史
  v25/Trust18、冻结 v24/Trust18、历史 v23/Trust17、冻结 v22/Trust16、IAM41/Trust14 与 IAM40/Trust13
  也未生成，v9/Trust5 drill01 只作历史，不能勾销这项门禁；
- [ ] 对保留数据执行加密离机备份并完成定期恢复、PITR、告警和依赖高风险处置。

此前 v21 的 IAM42/Demand11/Trust15 fresh-stack、十账号 journey、provider-only journey 与
stop/resume/restart 本地动态门禁已经勾选，只能作为“曾在 v21 完成本地合成动态验收”的历史证据；
冻结的 IAM42/Demand12/Trust16 v22 runtime/source 也曾独立完成 fresh journey 与 restart 验收，
v23/Trust17、冻结 v24/Trust18 与历史 v25/Trust18 也各自独立完成本地合成 fresh-volume journey 与 restart
验收；但这些历史结果不是 current-head v27 动态证据。v27 发布状态仍是
`STATIC VERIFIED / NOT PRODUCTION EXECUTED`。真实存量 preflight、视觉 QA、backup/restore 动态演练、
加密离机备份、定期恢复、PITR、告警和依赖风险仍未关闭，不能称为已生产发布或可生产部署的平台。
它始终只属于
`INTERNAL_SANDBOX`，不改变 G1/G2 结论。
