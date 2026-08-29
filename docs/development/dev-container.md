# Dev Container 开发指南

## 用途与边界

`.devcontainer/devcontainer.json` 组合 `compose.yaml` 与 `compose.dev.yaml`，启动
`devcontainer` 和 PostgreSQL 18。它固定 INTERNAL_SANDBOX，不自动启动 API/Web，
也不启用外部参与者。overlay 固定 Compose project 为
`desire-supply-devcontainer`，不会复用其他 project 的网络、容器和 PostgreSQL
volume；一次性验收仍可以用显式
`--project-name` 进一步隔离。Post-create 从仓库中的三个锁文件初始化三个开发面：
MVP 使用 `uv sync --locked`，Platform 使用
`uv sync --locked --extra test --extra server`，Web 使用与 CI 和生产镜像
一致的 `npm ci --ignore-scripts --no-audit`。后者只是关闭安装阶段的非门禁
audit 与供应链 lifecycle scripts；高风险漏洞仍由 CI 独立执行
`npm audit --audit-level=high` 并阻断。容器编排静态
验证必须先在有 Docker Compose CLI 的宿主机执行；Dev Container 默认不挂载 Docker
socket，也不获得宿主机 daemon 权限。

`devcontainer` 与它复用的 `db` 都固定 Docker `local` 日志 driver，options 精确为
`max-size=10m`、`max-file=3`、`compress=true`；base 和 development resolved config 的静态测试会
逐 service 校验。该配置只在容器创建时进入 `HostConfig.LogConfig`，所以重开同一已存在容器不会
回填新策略，删除/重建容器则会丢失旧容器日志。名义上限约 30 MiB/容器，不是 Audit、集中采集、
告警、备份或敏感数据擦除机制。

Dev Containers 的 editor 启动路径不能像手工命令一样由本仓库证明它一定传入显式
`--project-name`，而宿主机非空 `COMPOSE_PROJECT_NAME` 会覆盖 file-level `name:`。
因此 host `initializeCommand` 在 Compose 解析前 fail-closed：该变量非空时只输出
`BLOCKED:DEVCONTAINER_COMPOSE_PROJECT_NAME` 并退出 64，不输出变量值，也不尝试启动；
使用 **Reopen in Container** 前必须 unset 该变量。手工与 fresh 审计命令仍全部显式传入
`--project-name`，不依赖 file-level 名称或宿主环境。

开发镜像复用仓库已有的 digest-pinned Python、Node 和 uv 来源，并以 digest-pinned
PostgreSQL 开发基底提供客户端：精确合同是 Python 3.14.1、uv 0.9.15、
Node 22.22.3 和 PostgreSQL 18.4。镜像构建会逐项校验实际二进制版本，CI 也构建同一
`devcontainer` target。任何 ARG 默认值或二进制漂移都会在镜像构建或静态合同测试失败。
Python 与 Node source stage 都用同一个 fail-closed ELF/ldd/dpkg closure 生成 OS runtime
包清单，最终 PostgreSQL 18 base 在复制 `/usr/local` 前安装两份清单；因此 Node 在不同
架构上出现的额外动态库（例如 ARM64 的 `libatomic1`）也由实际 ELF 依赖决定，而不是靠
手写架构分支。最终 `node` 用户工具链门禁会吞掉底层命令输出，每个失败面只输出一个稳定
`BLOCKED:DEVCONTAINER_*` 标签并退出 1；全部通过时只输出
`READY:DEVCONTAINER_TOOLCHAIN`。`npm --version` 与 `npm --help` 都保留为真实门禁，
分别失败到 `BLOCKED:DEVCONTAINER_NPM_VERSION` 和
`BLOCKED:DEVCONTAINER_NPM_HELP`，不通过删除 help 或猜测依赖来绕开。npm 10.9.8 的
`npm --help` 正常会在输出 usage 后退出 1，因此 help 门禁捕获但不泄漏底层输出，允许状态
0 或 1，并要求至少一行精确等于 `Usage:` 或 `npm <command>`；状态大于 1、空输出或没有
闭合 usage 签名才阻断。
官方 PostgreSQL 18.4 基底声明 `VOLUME /var/lib/postgresql`。base `db` 继续把既有 named
volume 挂到 child `/var/lib/postgresql/data`，并保持
`PGDATA=/var/lib/postgresql/data/pgdata`；同时以参数
`rw,nosuid,nodev,noexec,size=1m` 的 1 MiB tmpfs 显式覆盖 parent
`/var/lib/postgresql`，防止镜像声明生成匿名 parent volume。这里的 parent tmpfs 与 child
named mount 是有意的嵌套挂载，不能把 named volume 的 target 移到 parent。开发 overlay
不重复覆盖 `db`；它只为同样基于官方 PostgreSQL 镜像、但不运行数据库的 `devcontainer`
保留同一 parent tmpfs，因此不会遗留无用途的匿名 PostgreSQL volume。

PostgreSQL backup/restore profile 仍只能从宿主机运行。虽然 Dev Container 现在有 18.4 的
`psql`、`pg_dump` 和 `pg_restore`，没有 daemon socket 就不能创建隔离 project/volume。
不要为了运行运维演练而挂载 `/var/run/docker.sock`、用户目录中的 Docker socket 或启用
`privileged`。开发容器可以审阅脚本、运行普通 Python/平台测试；Compose 静态验证和实际
恢复演练保留在宿主机。

镜像固定创建 `node` 用户与组（初始 UID/GID 1000）、home、`/bin/bash` 和只授予该用户的
NOPASSWD sudo；Dev Containers 的 UID 更新保持开启，以兼容 Linux 宿主机的 workspace
bind mount。镜像构建仍单独断言初始 UID 为 1000；运行期工具链门禁则接受 Dev Containers
映射后的任意非 root UID，并继续要求用户名为 `node`。`HOME` 与 npm cache 也显式固定在
`/home/node` 下；构建时的
`DEBIAN_FRONTEND=noninteractive` 不会泄漏到交互式开发环境。为了让 sudo 真正可用，
开发 overlay 不设置 `no-new-privileges` 或
`cap_drop: ALL`。这是仅用于本地开发的明确例外，不是生产部署基线：容器默认用户和编辑器
remote user 仍是 `node`，且没有 Docker socket、`privileged` 或端口发布。

`devcontainer` 只额外连接一个不发布端口的 `dev-egress` 网络，用于 post-create 下载
锁文件指定的依赖；`db` 仍只在内部数据网络。应用 API、数据库和 Web 都不会因此暴露到
宿主机或公网。开发 overlay 为三个网络设置显式 IPAM，但不固定 gateway：`app` 默认使用
`${DESIRE_DEVCONTAINER_APP_SUBNET:-172.16.221.0/24}`，`data` 默认使用
`${DESIRE_DEVCONTAINER_DATA_SUBNET:-172.16.222.0/24}`，`dev-egress` 默认使用
`${DESIRE_DEVCONTAINER_EGRESS_SUBNET:-172.16.223.0/24}`。`app` 和 `data` 继续继承 base
Compose 的 `internal: true`，`dev-egress` 保持非 internal。依赖安装结束后仍应使用
`--offline --locked` 运行平台测试。

这些 CIDR 只是当前宿主机上的默认候选，不是跨宿主机通用保证。每次首次启动或网络环境
变化后，启动前必须枚举 daemon default-address-pools、全部 Docker CIDR、宿主直连路由、
LAN 路由和 host/VPN 路由；不能只检查正在使用的 Compose project。预检必须区分两个网络
层次：Docker Desktop 把 Engine、`docker0` 和 user-defined bridge 放在 Linux VM 内，容器
出站再由 Desktop backend 在宿主机发起普通连接。因而宿主路由表中的宽覆盖路由不等同于
VM 内已经存在同一条 bridge CIDR；但 VPN、代理和防火墙仍会影响 backend 发出的真实流量。
这与 Docker 官方的
[Desktop networking](https://docs.docker.com/desktop/features/networking/) 和
[VPN how-to](https://docs.docker.com/desktop/features/networking/networking-how-tos/#working-with-vpns)
描述一致。

候选固定为 `/24` 时，fail-closed 阻断规则是：与任一 daemon default pool 或全部 Docker
network CIDR 重叠；与任一 LAN/direct CIDR 重叠；或者与 host/VPN route 重叠且该 route
也是 `/24` 或更具体。前两类不因 route 较宽而放行。覆盖更宽的 host/VPN route（prefix
小于 24），包括 `default`、`0.0.0.0/0` 以及全隧道 VPN 常见的 `0.0.0.0/1`、
`128.0.0.0/1`，只记录 caveat，不能单独把它当作 VM bridge CIDR 冲突。这不是安全性或
可达性保证：VPN 断开时无冲突不代表连接后可用，caveat 也不能被静默丢弃。若出现任一
阻断项，必须先选择三段互异的 RFC1918 `/24`，再通过
`DESIRE_DEVCONTAINER_APP_SUBNET`、`DESIRE_DEVCONTAINER_DATA_SUBNET` 和
`DESIRE_DEVCONTAINER_EGRESS_SUBNET` 显式覆盖；不得退回 daemon 自动分配，也不得显式
固定 gateway。可以先进行只读枚举，并根据 route 的 gateway、interface 和 flags 明确区分
LAN/direct 与 host/VPN；不能只按文本“overlap”合并分类：

```bash
docker info --format '{{ json .DefaultAddressPools }}'
docker network ls -q | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}'
netstat -rn
```

网络创建后还必须在**同一 VPN/路由状态**下执行创建后端到端网络验证：从
`devcontainer` 内解析并探测 `db:5432`，验证实际需要的 DNS/TLS 出站端点，并从容器内
探测本次开发确实依赖的非敏感 LAN/VPN 测试端点。只看宿主机 `netstat`、只看 network
inspect，或宿主机自身能访问目标，都不能替代该验证；如果没有可安全探测的业务端点，必须
把这一项明确记为未验证，不能宣称 VPN/LAN 可达。

确认默认候选在当前路由环境确实无冲突后，可显式固定本次 shell；若存在冲突，先替换右侧
三个值再继续：

```bash
export DESIRE_DEVCONTAINER_APP_SUBNET="172.16.221.0/24"
export DESIRE_DEVCONTAINER_DATA_SUBNET="172.16.222.0/24"
export DESIRE_DEVCONTAINER_EGRESS_SUBNET="172.16.223.0/24"
```

Dev Container 把其专用 `db` 明确标记为可销毁 integration-test PostgreSQL，并通过
Docker secret 在容器启动时生成 mode 0600 的 `/tmp/desire-pgpass`。密码不会进入 DSN、
普通环境变量、镜像层或日志；`/tmp` 是随容器停止销毁的 tmpfs。开发容器中的 Platform
测试会在 Python `tempfile` 目录创建并执行隔离 fixture，所以 overlay 必须把这一处 tmpfs
精确挂载为 `rw,exec,nosuid,nodev,size=64m`。这是开发专用的显式执行例外；base Compose
及生产服务继续保持 `/tmp` 为 `rw,noexec,nosuid,nodev,size=64m`，PostgreSQL parent tmpfs
也继续 `noexec`。不能把开发例外复制到生产 hardening。secret 缺失、过短、包含多行或
无法安全编码为 pgpass 时，容器以稳定 `BLOCKED` 状态停止。不要把这个测试 DSN 指向共享
或需要保留数据的数据库。

## VS Code / Dev Containers

1. 在宿主机完成上一节要求的全部 Docker CIDR、宿主直连路由和更具体路由枚举；冲突时先
   显式覆盖三个 subnet 变量。
2. 在宿主机创建 `secrets/db_superuser_password.txt`；只启动 db/devcontainer 不需要
   完整产品 runtime secret 集，步骤见容器部署运行手册。
3. 在仓库根目录执行 `python3 -B scripts/verify_container_stack.py`；必须输出
   `{"status":"OK"}`。
4. 确认宿主 shell 的 `COMPOSE_PROJECT_NAME` 未设置，然后在 VS Code 打开仓库根目录。
5. 执行 **Dev Containers: Reopen in Container**。
6. 等待 post-create 完成；成功末行应为
   `{"status":"DEVCONTAINER_DEPENDENCIES_READY"}`。
7. 在容器终端检查：

```bash
/usr/local/bin/desire-devcontainer-toolchain-check
cd /workspace/mvp && uv run --offline --locked python -m unittest discover -s tests -v
cd /workspace/platform && uv run --offline --locked --extra test --extra server python -m unittest discover -s tests -t . -v
cd /workspace/web && npm test
```

Platform venv、MVP venv、Web node_modules、uv cache 和 npm cache 分别保存在五个 named
volumes，避免宿主机架构的 `.venv` 或 `node_modules` 污染容器；源码仍由 `/workspace`
bind mount 提供。entrypoint 会在每次启动时用 `sudo -n` 把这五个 mount root（且只包含
root 本身）调整为当前 `node` UID/GID，以承接 `updateRemoteUserUID`；它不会递归 chown，
也不会改 `/workspace` bind mount。工具链门禁会在 post-create 后再次确认当前用户不是
root、仍名为 `node`，并确认 `/home/node` 与这五个 mount root 都存在且可写；因此 Linux
宿主把 `node` 映射为 1001 等 UID 时不会被镜像初始 UID 合同误拦截，权限修复失败则会以稳定
`BLOCKED:DEVCONTAINER_HOME` 或 `BLOCKED:DEVCONTAINER_DEPENDENCY_ROOT` 标签停止。上述版本与
权限是静态和镜像构建合同，不替代一次
fresh project 动态验收。隔离 v1 在 Python closure 的非 ELF config 候选处 fail-closed；
隔离 v2 的最终 `node` 用户多工具链静默门禁整体 exit 1；因 v2 没有分项标签，具体失败
子项未知。隔离 v3 已通过 Python 与 Node 的 OS runtime closure、Python version/import 和
Node version，随后只在当时合并的 `npm --version`/`npm --help` 门禁 fail-closed，因此仍
不能仅凭该 build 日志判断是 version 还是 help 子命令失败。后续本机诊断证明 npm 10.9.8
的 version 子命令退出 0，而 help 会输出 usage 并正常退出 1。v1、v2、v3 都停在镜像
build、未进入 Compose
启动，各自留下的运行资源均为 0。隔离 v4 的唯一 build 已 GREEN；唯一 up 在创建第三个
`data` network 时因 daemon 默认地址池耗尽而 IPAM blocked，未进入 post-create。v4 project
永久保全且不得重试，终态为 0 containers、0 volumes、2 networks：零端点的 internal
`app=192.168.144.0/20` 与非 internal `dev-egress=192.168.128.0/20`，`data` 未创建。
隔离 v5 的唯一 build 与唯一 up 均 GREEN，精确创建并保留 2 containers、3 networks 与
6 volumes；db healthy，两个容器均无 host port binding。随后 operator 在 post-create 前的
组合 smoke 中额外断言非交互 `sh -lc` 必须设置 `$SHELL`，该非合同变量未设置并触发
`set -u` exit 2。这个 harness 错误不等于 passwd 中 `node` 的 shell 不是 `/bin/bash`，也
没有证伪候选；但按一次性规则 v5 不再执行任何命令，post-create 与三面 locked tests 均未
运行。project `desire-supply-devcontainer-audit-20260819-v6` 已固定；隔离 v6 的唯一 build 与唯一 up 均 GREEN，
创建 2 containers、三个 project networks
`172.16.224.0/24`、`172.16.225.0/24`、`172.16.226.0/24`，以及 6 个
Compose-declared/project-labeled volumes；但容器实际 volume sources 为 7，db target `/var/lib/postgresql`
额外恰好 1 个 anonymous local volume，且没有 Compose labels。既有
named `postgres-data` 仍精确挂到 `/var/lib/postgresql/data`，并保持
`PGDATA=/var/lib/postgresql/data/pgdata`。因此 v6 topology RED：它保持 db healthy、
devcontainer running，未 stop/down/rm/prune，post-create 与 MVP/Platform/Web tests 均为 0；
不得重试、清理或补跑。随后 v7 source/static 20/20、verifier、docs 与 diff 均 GREEN，
`compose config --quiet` 精确 exit 0。operator 的额外 in-memory assertion 错误地要求
top-level rendered JSON network keys 带 project 前缀；实际逻辑 keys 是
`app`、`data`、`dev-egress`，project-specific 名称只在各 network 的 `name` 字段。该额外断言
exit 1，且发生在 build 之前；所以 v7 project/network/volume/tag 全部 absent：project
`desire-supply-devcontainer-audit-20260819-v7`、三个 network、全部 volume 与
`DESIRE_IMAGE_TAG="devcontainer-audit-20260819-v7"` 都不存在，build=0、up=0。候选未被证伪，
但一次性规则仍要求不得重跑 v7。下一轮必须使用全新、唯一的
`desire-supply-devcontainer-audit-20260819-v8` project，不能复用 v1–v7。v8 的只读宿主
route preflight 又把全隧道 VPN 的 `128.0.0.0/1` 按“任意 host route overlap”过严判为
RED；这发生在 build 前，build=0、up=0，v8 project/network/volume/tag 全部 absent。
其中 absent tag 精确为 `DESIRE_IMAGE_TAG="devcontainer-audit-20260819-v8"`。
`/1` 只证明 VPN 覆盖候选地址，不证明 Docker Desktop VM 内已有同一 bridge `/24`；但
v8 仍按一次性证据锁定，不得重跑。隔离 v9 的唯一 build 与唯一 up 均 GREEN；正式
`v9 topology GREEN` 证据是 `containers=2`、`networks=3`，三个网络分别为
`app=172.16.233.0/24 internal=true endpoints=1`、
`data=172.16.234.0/24 internal=true endpoints=2`、
`dev-egress=172.16.235.0/24 internal=false endpoints=1`。它还精确证明
`named/project-labeled volumes=6`、`actual volume mounts=6`、
`anonymous volumes=0`、`host port bindings=0`、`privileged=0`；其中
db parent `/var/lib/postgresql` 是 tmpfs，child `/var/lib/postgresql/data` 是 named volume。
随后 operator runtime harness 在 post-create 前构造嵌套 `awk` 命令时，由外层 shell
错误展开了位置参数 `$7`，以 `sh: 7: 7: parameter not set`、exit 1 结束。这个错误只使
harness invalid，候选不是 RED；`post-create=0`、`MVP/Platform/Web locked tests=0`。
v9 project `desire-supply-devcontainer-audit-20260824-v9` 与
`DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v9"` 保持 running，并按一次性规则不得重试、stop、down、rm 或 prune。
因此 v9 占用导致 172.16.233.0/24、172.16.234.0/24、172.16.235.0/24 均被阻断，后续 project 不得复用。
隔离 v10 的动态 preflight 全部 GREEN，候选、静态门、initialize、secret metadata、namespace absence、Docker CIDR 与 route helper 均已闭合。
随后唯一 build 前的自制 V8 operator wrapper 把无效对象键写成 `" Dockerfile".trim():`，解析阶段立即返回
`SyntaxError: Unexpected token '.'`；耗时为 `0.0s` 且 `nested exec=0`，所以
`candidate rehash=0`、`build=0`、`up=0`，project/network/volume/tag 仍全部 absent。
其中 project 精确为 `desire-supply-devcontainer-audit-20260824-v10`，absent tag 精确为
`DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v10"`。
这没有进入 Docker，也没有改变 v9；候选未被证伪，但一次性证据规则要求不得复用 v10。
隔离 v11 的唯一 build 与唯一 up 均 GREEN，`v11 topology GREEN`，工具链、用户、权限、
PostgreSQL 18、数据库 DNS/5432 和 PyPI DNS/TLS 的 runtime smoke GREEN；唯一 post-create
也为 `post-create GREEN`，MVP locked tests 134/134 GREEN。随后 Platform locked tests 1072
以 1 failure + 16 errors、exit 1 结束。其中唯一 failure 是
`test_external_ephemeral_pg18_dsn_runs_the_same_gate_without_docker` 返回
`IAM_0024_TEST_PYTHON_UNAVAILABLE`：overlay 的 `/tmp` 没有显式 `exec`，导致测试在
Python `tempfile` 下生成的 0700 fixture 不可执行。其余 errors 暴露外部 PostgreSQL harness
的角色/凭据兼容问题，与这项 tmpfs 修复分开闭合。失败后没有运行 Web，精确记录为
`Web tests/typecheck/lint=0`；因此 v11 动态 RED，project
`desire-supply-devcontainer-audit-20260824-v11`、
`DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v11"` 与三段网络
`172.16.236.0/24`、`172.16.237.0/24`、`172.16.238.0/24` 保持 running。该坐标不得重试、
stop、down、rm 或 prune，也不得复用 v11。隔离 v12 的
host preflight 只完成 hashes/static/initialize/secret stat，且这些已执行项全部 GREEN；
`CIDR/route enumeration=0`。随后 generic symlink check 调用了 macOS 上不存在的
`/usr/bin/test`，以 exit 127 结束。这发生在读取任何文件内容之前，且
`错误前 Docker command=0`。随后只执行 read-only preservation audit，进一步确认精确终态
`build=0`、`up=0`、`Docker mutation=0`，v12 project/network/volume/tag 全部 absent；
v11 保持 untouched。候选没有被这次失败证伪，
但 v12 是 operator harness-invalid，一次性规则仍要求不得重试或复用 v12。该锁定坐标为
project `desire-supply-devcontainer-audit-20260824-v12` 与
`DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v12"`。
隔离 v13 的唯一 build 与唯一 up 均 GREEN，且 `v13 topology GREEN`：
`v13 containers=2`、`v13 networks=3`，网络精确为
`app=172.16.242.0/24 internal=true endpoints=1`、
`data=172.16.243.0/24 internal=true endpoints=2`、
`dev-egress=172.16.244.0/24 internal=false endpoints=1`；同时证明
`v13 named/project-labeled volumes=6`、`v13 actual volume mounts=6`、
`v13 anonymous volumes=0`、`v13 host port bindings=0`、`v13 privileged=0`。
runtime smoke #1-#4 exit 0。PyPI smoke #5 使用 GET `/simple/`，在 20s 内已收到
`11,463,474/45,294,663 bytes` 后仍以 exit 28 超时，因为该路径会下载完整 large index，
不是轻量 availability probe。按顺序停止规则，`smoke #6 execution=0`，
`post-create/toolchain/MVP/Platform/Web execution=0`。project
`desire-supply-devcontainer-audit-20260824-v13` 与
`DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v13"` 及其资源均 v13 保持 running/locked；
v13 不得重试、stop、down、rm 或 prune。隔离 v14 的 fresh preflight、唯一 build、唯一 up、
`v14 topology GREEN`、六项 runtime smoke、唯一 post-create、工具链与 MVP locked tests
134/134 均 GREEN。随后 Platform locked tests 在 `Ran 1091 tests in 157.827s` 后以
`14 errors、0 failures`、exit 1 结束：Identity bootstrap 的首项通过后有 7 个 setup
`MigrationConnectionLost`，IAM36 的首项通过后有 3 个同类 setup error，taxonomy seed 的
首项通过后有 4 个 `taxonomy_migration_runner` password authentication error；因此
`Web tests/typecheck/lint=0`。根因是外部 PostgreSQL cluster 的 fixed roles 跨 test database
持久存在，而这些测试会按合同清除或失效临时 LOGIN 凭据；旧 harness 在分配下一数据库前
没有恢复同一 harness marker 所有 LOGIN roles 的 runtime password 与
`VALID UNTIL '9999-01-01 00:00:00+00'`。该远期有限值在所有时区偏移下仍可被 psycopg
解码，同时会把 `epoch` 撤销态恢复为可用的临时 harness 凭据；这些 marker-owned roles
仍会随 disposable harness 清理。修复已用 21/21 外部 harness 回归、原受影响真实
PostgreSQL 18/18、online credentials 3/3 和 session-drain contract 2/2 闭合，但
v14 已按一次性规则锁定，project
`desire-supply-devcontainer-audit-20260824-v14`、
`DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v14"` 与
`172.16.245.0/24`、`172.16.246.0/24`、`172.16.247.0/24` 保持 running；不得重试、stop、
down、rm、prune 或补跑 Web。下一轮坐标固定为全新 project
`desire-supply-devcontainer-audit-20260824-v15` 与
`DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v15"`。隔离 v15 的 fresh preflight、唯一
build、唯一 up 与 `v15 topology GREEN` 均通过：2 containers、3 networks、
6 个 named/project-labeled volumes、6 个 actual volume mounts、0 anonymous volumes、
0 host port bindings、0 privileged；三个网络精确为
`app=172.16.248.0/24 internal=true endpoints=1`、
`data=172.16.249.0/24 internal=true endpoints=2`、
`dev-egress=172.16.250.0/24 internal=false endpoints=1`。六项 runtime smoke、唯一
post-create、工具链、MVP `Ran 134 tests in 2.075s`、Platform
`Ran 1096 tests in 176.405s`、Web `70/70`、typecheck 与 lint 全部 GREEN。验收后的 exact
project guard、`ps -a`、多行 ID capture 与 non-empty guard 也为 GREEN；随后文档中的
`for DESIRE_DEV_AUDIT_ID in $DESIRE_DEV_AUDIT_IDS` 在 zsh 下把两个换行分隔的 ID 保留为
一个 scalar，`docker inspect` 因 `no such object` 以 exit 1 失败。`down execution=0`，所以
v15 cleanup RED，project `desire-supply-devcontainer-audit-20260824-v15`、
`DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v15"` 与 `172.16.248.0/24`、`172.16.249.0/24`、
`172.16.250.0/24` 保持 running/locked；不得重试、stop、down、rm 或 prune。隔离 v16 随后在
全新 project `desire-supply-devcontainer-audit-20260824-v16` 与
`DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v16"` 完成 fresh preflight、唯一 build、唯一
up 和 topology 验收；build 产物 digest 为
`sha256:a74ae5198a9a6b2042f99754d93df9b695c86edb071179b0387c733bd401cf20`。运行态精确为
2 containers、3 networks、6 个 named/project-labeled volumes、6 个 actual volume mounts、
0 anonymous volumes、0 host port bindings、0 privileged；三个网络精确为
`app=172.16.251.0/24 internal=true endpoints=1`、
`data=172.16.252.0/24 internal=true endpoints=2`、
`dev-egress=172.16.253.0/24 internal=false endpoints=1`。六项 runtime smoke、唯一
post-create、工具链、MVP `Ran 134 tests in 0.594s`、Platform
`Ran 1096 tests in 177.973s`、Web `70/70`、typecheck 与 lint 全部 GREEN。cleanup 先精确
确认 2 个容器，再分别捕获 db/devcontainer ID，逐个验证 non-empty、互异且 Compose project
label 精确匹配；唯一 scoped `down --volumes --remove-orphans` 成功删除 2 containers、3 networks
与 6 volumes，随后 label 枚举精确为 `0/0/0`。v16 动态验收与销毁 GREEN；该 project、tag
与三段 CIDR 已成为一次性历史坐标，不得复用或重放。

## 不使用编辑器时

三条日常命令都显式固定 project 名；即使宿主机已设置 `COMPOSE_PROJECT_NAME`，也不能把
启动、进入或停止操作改到其他 Compose project。

```bash
docker compose --project-name desire-supply-devcontainer -f compose.yaml -f compose.dev.yaml up -d db devcontainer
docker compose --project-name desire-supply-devcontainer -f compose.yaml -f compose.dev.yaml exec devcontainer sh
```

日常结束只停止这两个开发服务，不销毁 project 或 named volumes：

```bash
docker compose --project-name desire-supply-devcontainer -f compose.yaml -f compose.dev.yaml stop devcontainer db
```

完整产品栈现在会依次执行 migration、taxonomy seed、online credential 与 identity
bootstrap，并启动真实 API composition；Dev Container 的 `runServices` 仍只包含 db 与
devcontainer，不会隐式运行这条链。开发某一入口时应在 devcontainer 终端显式运行它，
再用测试证明其授权和健康边界。

## Fresh project 动态验收（v16 已完成）

下面保留的是 v16 已逐条执行并完成销毁的不可重放证据协议，不是可再次执行的日常命令。
如需取得下一轮 fresh 证明，必须先经静态评审把文档、verifier、测试与 CI 一起滚到全新的
project、tag 和三个未占用 CIDR；不得只在终端临时替换 v16 字符串。v16 当轮先完成上面的
CIDR/路由枚举，并在同一个 shell 中保留唯一且明确可销毁的 project 名。
v5 占用默认三段，仍在运行且必须保全的 v6 占用 `172.16.224.0/24`、
`172.16.225.0/24` 和 `172.16.226.0/24`；v13 与 restore 还预留或占用相邻网段。v7 在
build 前退出且没有消费任何资源，v8 也只因宽 `/1` 的错误分类在 build 前退出。v11、v13
、v14 与 v15 都已锁定并占用各自三段；v12 没有消费候选网段，但坐标及候选网段均不得复用。v16
固定把 `172.16.251.0/24`、`172.16.252.0/24`、`172.16.253.0/24` 作为候选，但只能在
最新只读预检确认没有 Docker CIDR、LAN/direct，或 `/24` 等长/更具体 host/VPN route
冲突后使用；静态 rollforward 不表示它们当前可用，v16 必须重新完成 fresh preflight。
不得通过改动仍在运行的 v9、v11、v13、v14 或 v15 来腾挪地址，也不得复用任何旧候选三段。
它只启动 `db` 和 `devcontainer`，不启动或挂载其他 project。v16 动态 operator 禁止任何自制 JavaScript、V8 或组合 wrapper；
必须逐条直接执行审定命令，并在进入下一条前逐项记录退出码。不能把整个段落复制进新的
编排脚本，也不能把独立门禁重新包装成一个合并退出码。

```bash
export DESIRE_DEV_AUDIT_PROJECT="desire-supply-devcontainer-audit-20260824-v16"
export DESIRE_IMAGE_TAG="devcontainer-audit-20260824-v16"
export DESIRE_DEVCONTAINER_APP_SUBNET="172.16.251.0/24"
export DESIRE_DEVCONTAINER_DATA_SUBNET="172.16.252.0/24"
export DESIRE_DEVCONTAINER_EGRESS_SUBNET="172.16.253.0/24"
test "${DESIRE_DEV_AUDIT_PROJECT:-}" = "desire-supply-devcontainer-audit-20260824-v16"
test "${DESIRE_IMAGE_TAG:-}" = "devcontainer-audit-20260824-v16"
```

宿主 metadata 检查必须使用 POSIX shell builtin `test`（或确定存在的 `/bin/test`），不能再
硬编码上一轮不存在的绝对路径。先逐条确认 secret leaf 不是 symlink 且是普通文件；
这两条只读 metadata，不读取 secret 内容，也不能包装成自制脚本：

```bash
test ! -L secrets/db_superuser_password.txt
```

```bash
test -f secrets/db_superuser_password.txt
```

以下 build 与 up 各自只能执行一次；每个代码块都是一条独立宿主命令，前一条 exit 0
才允许执行后一条：

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml build devcontainer
```

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  up -d --wait --wait-timeout 120 db devcontainer
```

build 或 up 任一非零都必须立即锁定 v16，禁止重试、补跑、清理或继续。

下面六个 runtime smoke 也必须逐条直接运行并分别记录退出码，不得合并。第二项把一个
已知可执行的最小二进制复制进 `/tmp` 后直接运行，证明开发专用 tmpfs 没有退回隐式
`noexec`：

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T devcontainer sh -lc \
  'test "$(getent passwd node | cut -d: -f7)" = "/bin/bash"'
```

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T devcontainer sh -lc \
  'install -m 0700 /bin/true /tmp/desire-devcontainer-tmp-exec-check && "/tmp/desire-devcontainer-tmp-exec-check"'
```

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T devcontainer getent ahostsv4 db
```

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T devcontainer pg_isready -h db -p 5432
```

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T devcontainer curl --head --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' \
  --max-time 20 --output /dev/null https://pypi.org/simple/
```

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T devcontainer curl --head --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' \
  --max-time 20 --output /dev/null https://registry.npmjs.org/
```

这两个 HEAD 只证明轻量 DNS/TLS/HTTP availability，不下载 response body；
`--proto '=https' --proto-redir '=https'` 还禁止 redirect 降级到明文协议。当前端点已独立测得
`HTTP 200、redirects=0、size_download=0`。它们不替代真实 GET/package body/CDN 门禁；
后续 `uv sync` 与 post-create 中的 `npm ci` 继续覆盖真实 GET/package body/CDN，不增加
解析状态码的自制 wrapper。

六项 runtime smoke 任一非零都必须立即锁定 v16，禁止重试、补跑、清理或继续。
只有六项都 exit 0，才逐条直接执行唯一 post-create：

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T devcontainer sh -lc \
  'cd /workspace/mvp && uv sync --locked && /usr/local/bin/desire-devcontainer-post-create'
```

唯一 post-create 若非零，也必须立即锁定 v16，禁止执行工具链和后续测试；不得重试、补跑
或清理该坐标。

然后把工具链、MVP、Platform、Web test、typecheck 和 lint 分成六条直接命令；每条都必须
单独记录退出码，任一失败就立即锁定 v16，后续检查不得补跑：

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T devcontainer /usr/local/bin/desire-devcontainer-toolchain-check
```

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T -w /workspace/mvp devcontainer \
  uv run --offline --locked python -m unittest discover -s tests -v
```

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONPATH=src \
  -w /workspace/platform devcontainer \
  uv run --offline --locked --extra test --extra server \
  python -m unittest discover -s tests -t . -v
```

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T -w /workspace/web devcontainer npm test
```

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T -w /workspace/web devcontainer npm run typecheck
```

```bash
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" \
  -f compose.yaml -f compose.dev.yaml \
  exec -T -w /workspace/web devcontainer npm run lint
```

验收后仍在同一个 shell 中先列出该 project 的对象，再逐个核对 Compose project label。
只有所有 label 都精确等于刚生成的唯一名称，才销毁这个可丢弃 project：

```bash
test "${DESIRE_DEV_AUDIT_PROJECT:-}" = "desire-supply-devcontainer-audit-20260824-v16"
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" -f compose.yaml -f compose.dev.yaml ps -a
test "$(docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" -f compose.yaml -f compose.dev.yaml ps --all --quiet | wc -l | tr -d '[:space:]')" = "2"
DESIRE_DEV_AUDIT_DB_ID="$(docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" -f compose.yaml -f compose.dev.yaml ps -q db)"
test -n "$DESIRE_DEV_AUDIT_DB_ID"
DESIRE_DEV_AUDIT_DEVCONTAINER_ID="$(docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" -f compose.yaml -f compose.dev.yaml ps -q devcontainer)"
test -n "$DESIRE_DEV_AUDIT_DEVCONTAINER_ID"
test "$DESIRE_DEV_AUDIT_DB_ID" != "$DESIRE_DEV_AUDIT_DEVCONTAINER_ID"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' "$DESIRE_DEV_AUDIT_DB_ID")" = "$DESIRE_DEV_AUDIT_PROJECT"
test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' "$DESIRE_DEV_AUDIT_DEVCONTAINER_ID")" = "$DESIRE_DEV_AUDIT_PROJECT"
unset DESIRE_DEV_AUDIT_DB_ID DESIRE_DEV_AUDIT_DEVCONTAINER_ID
docker compose --project-name "$DESIRE_DEV_AUDIT_PROJECT" -f compose.yaml -f compose.dev.yaml down --volumes --remove-orphans
unset DESIRE_DEV_AUDIT_PROJECT
```
