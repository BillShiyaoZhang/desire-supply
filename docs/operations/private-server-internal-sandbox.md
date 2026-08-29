# 私有服务器 INTERNAL_SANDBOX 入口

状态：`INACTIVE · INTERNAL_SANDBOX · SYNTHETIC ONLY · G1 NO-GO · G2 NO-GO`。

本页只定义一个默认不启用的私有 IPv4 HTTPS 入口。它让受控内网中的合成角色在未来可以访问
服务器上的现有工作台，但不批准真人数据、真实合同、真实资金、真实权益决定、公开注册或公网
发布。基础 `compose.yaml` 继续只绑定 `127.0.0.1:443`；只有操作者显式叠加
`deploy/private-server.compose.yaml` 时，才会增加第二个、命名的 RFC1918 `:443` bind。

真实 provider 不属于本激活合同。独立、同样 inactive 且不授权启动的配置边界见
[私有服务器真实 OIDC 静态配置](/operations/private-server-real-oidc.md)；现有 activator 与 manager
不得加载该叠层。

## Release candidate 证据边界

仓库提供关闭式的
`deploy/private-server-release-candidate-evidence-v1.schema.json` 和
`scripts/private_server_release_candidate_evidence.py`，只用于整理调用方对 current-head v13
（`RUN_CURRENT_HEAD_V13_ONCE`）的声明。v1 永久 fail-closed；它固定 `INTERNAL_SANDBOX`、`synthetic_only`、
`production_authorized=false`，并绑定 source snapshot、七项冻结摘要、Docker Hub 五个 ref 连续三轮
门禁、全量测试与质量检查、Trust8 applicant discovery 的受限延期，以及全部 v13 坐标仍未消费的
调用方子字段。当前状态示例必须保持：

```json
{"one_shot_v13":{"claim":"NOT_VERIFIED"},"overall_status":"BLOCKED"}
```

上面只是状态片段，不是可提交 artifact；完整 PENDING/BLOCKED 样本只在部署单测的临时 `0700`
目录中生成和验证，仓库当前不生成候选实例。工具只会把调用方提供、已通过关闭形状与本地绑定校验
的完整 JSON 规范化写到显式指定且尚不存在的路径，权限为 `0600`；它不会 overwrite 已有输出，
`verify` 只读。

v1 中的 `PASSED`、`VERIFIED` 和 `UNCONSUMED_VERIFIED` 子字段都只是未验证的 caller claim，不是
工具从权威来源取得的事实。无论这些子字段如何组合，`overall_status` 只能是 `BLOCKED`，并且
`blocking_reasons` 必须始终精确包含 `EVIDENCE_PROVENANCE_NOT_VERIFIED`；pending、failed、mismatch、
未核验 v13 坐标和未接受的 Trust8 延期还会增加各自的 blocker。任何下游都不得把任一 `PASSED`
子字段、整份 v1 artifact 或命令成功退出当作 readiness、批准或授权。人工批准必须是独立 artifact，
且本工具既不能表达 `APPROVED`，也不生成或验证批准。v1 永久关闭并作为 v13 历史格式保留；当前
manifest 已追加新头部时，旧 v1 对 current bytes 得到 `MISMATCH` 是诚实结果，不能改写其 expected hash。

v14 独立提供关闭候选格式
`deploy/private-server-release-candidate-evidence-v2.schema.json` 与
`scripts/private_server_release_candidate_evidence_v2.py`，使用
`trust_applicant_discovery_deferral`。v2 仍保持 `BLOCKED` / fail-closed，不读取受保护 receipts、不证明
当前资源的 live absence，也不授权部署、私服激活或生产使用；完整边界见
[Current-head v14 发布资产](/operations/current-head-v14.md)。仓库当前仍不生成任何真实证据实例。

这份候选证据不授权本页后续的非 v13 私服激活。实际私服 project、tag、input root、subnet、bind
IP、镜像 ID 和外部门禁必须在 v13 完成后进入另一份独立批准；不得把 release candidate artifact
直接传给激活器。

## 启用前的全部门禁

当前仓库保持入口 inactive，直到操作者显式运行下述原子激活程序；文档本身不创建容器、网络、
volume、输入、镜像或业务事实。不得使用任何 v13 project、tag、input、CIDR 或 evidence 坐标；实际尝试必须事先批准
一组新的、从未使用过的非 v13 坐标，并单独记录其 project、tag、input root、四个 Docker
subnet 和证据路径。

启用前必须同时具备：

- 一枚明确审核的 RFC1918 IPv4，已分配给目标 Linux 主机上处于 UP 状态的非 loopback 网卡；
- 从每一台受控客户端验证两个 `example.test` hostname 都只解析到该私网 IPv4；
- 仅在受控测试浏览器或受控测试用户 trust store 中安装本轮测试 root CA，并保持标准 TLS
  chain、hostname、OIDC discovery、JWKS 和 JWT 校验；
- 主机防火墙和云安全组都只允许审核过的私网来源 CIDR 访问 TCP/443，并证明没有公网 IP、
  wildcard ingress、NAT/端口转发或面向互联网的 load balancer；
- exact Platform、Web、Edge 与 PostgreSQL 镜像已经存在于目标主机，且其 image ID/digest 已由
  独立发布记录固定；激活过程只能使用 `--no-build --pull never`，不能现场 build、pull、tag
  或用 mutable tag 修复缺失镜像；
- 目标机固定安装 Docker Compose `5.3.1`、`/usr/bin/docker`、`/usr/sbin/ip`、`/usr/bin/ss`
  和 `/usr/bin/python3`；只允许本机 `unix:///var/run/docker.sock`。Docker、`ip`、`ss` 和实际
  Compose plugin 都必须是 root 所有、不可被 group/world 写入的可执行普通文件，不能是 symlink。
  `/usr/bin/python3` 可以是受信任的系统 symlink，但 launcher、每一层 symlink、最终目标及其每一级
  父目录都必须为 root 所有，整个链不能由 group/world 改写；每一级父目录以及链上的普通文件都必须
  不可被 group/world 写入，最终目标必须是可执行普通文件。Unix symlink 的 mode 位不承担访问控制，
  因此链接项由 root ownership 和不可写父目录保护；
- 在第一次触发 Docker CLI plugin discovery 前，激活器会仅按固定的四个 system Compose candidate
  位置闭合枚举，要求其父目录可信且恰好一个 `docker-compose` 存在，并固定该普通文件的 path 与
  SHA-256。attempt 的 `DOCKER_CONFIG` 必须精确只含 `config.json`，不能含 `cli-plugins`。每一条
  Compose 命令调用前后都会重新验证该目录，并重新闭合枚举全部 candidate、比对同一个 path 与摘要；
  任一新增高优先级或第二 system candidate 都会 fail closed；
- 目标主机上的新 input/TLS/runtime bundle 已由现有关闭 preparer 创建并验证；不得复制开发机
  的绝对路径 `compose.env`，不得把 secret 放入源码、镜像或发布归档；
- 发布 checkout 中激活器固定的 Compose、overlay、identity template、预检和两个验证 helper 必须为
  root 所有、不可被 group/world 写入且内容摘要与受审版本一致；`/var/lib/desire/private-ingress-attempts`
  必须预先存在，为 root 所有且权限精确为 `0700`；
- 目标私网 IPv4、IPv4/IPv6 wildcard 与基础 loopback `127.0.0.1` 上的 TCP/443 都没有既有
  LISTEN socket。

缺少任一事实都必须保持 overlay inactive。RFC1918 地址本身不等于访问控制；本预检不会猜测
主机防火墙、云路由、安全组、客户端 DNS 或 CA 安装是否正确。

## Linux 主机只读预检

在目标 Linux 主机、任何 Compose `up` 之前，用与 overlay 相同的显式地址执行：

```bash
/usr/bin/python3 -I -B scripts/preflight_private_server_ingress.py \
  --bind-ip "$DESIRE_PRIVATE_INGRESS_IP"
```

成功必须只输出：

```json
{"status":"PRIVATE_SERVER_INGRESS_PREFLIGHT_READY"}
```

预检通过只证明地址形状、网卡归属和本机监听冲突关闭。它不创建或修改网络状态，也不替代客户
端 DNS/CA 检查、主机防火墙/云安全组审批、镜像完整性、Compose 静态验证、数据库初始化、角色旅程、
restart、backup/restore、PITR、告警或人工视觉验收。

## 激活合同

获得全部外部门禁后，唯一受支持的入口是 fresh activate 程序；这是新 project 的首次激活，
不是 restart，也不能用于接管或修复已有 project。必须由 root 使用 `/usr/bin/python3 -I -B`
运行，不能省略 isolated mode。

`compose.env` 与 `compose.ipam.yaml` 必须位于同一个 root 所有、权限精确为 `0700`、无 symlink
的新 input root；两者和四个根级 secret 必须是 `0600` 普通单链接文件。这个 input root 还必须
精确包含本轮 identity source、TLS 和 runtime bundle，不能多出临时文件。IPAM 文件只可包含四个
网络各一个互不重复的 RFC1918 `/24`。TLS 文件的 PEM、证书链、hostname、有效期和私钥匹配必须
在本程序外先通过专门证书门禁；这里只锁定已经获批的 exact bytes。

发布审批记录必须固定以下值：

- 一个从未使用过的 project 名和非 v13 immutable image tag；
- Platform、Web、Edge、PostgreSQL 四个本机 image ID，格式均为 `sha256:` 加 64 位小写十六进制；
- 关闭 input tree 的 64 位小写 SHA-256。该值必须来自独立、受审的发布记录，不能在激活时临时
  改写为当前目录的摘要来让校验通过；
- 私网 bind IP、四个 subnet、客户端来源 allowlist、DNS 与 CA 审批证据。

在批准者记录上述摘要前，先由 root 对候选树执行只读 `measure`。执行下面任一 `sudo` 前，受信任
主机安装/配置门禁必须从 `/opt` 开始逐级确认 checkout、`scripts` 和
`private_server_release_inputs.py` 为 root 所有、不可被 group/world 写入且不是 symlink；不能让即将
以 root 加载的 Python 文件自证。bundle name 必须是候选 `compose.env` 指向的同一个关闭 basename，
不能从路径猜测或使用旧 release 的值：

```bash
sudo /usr/bin/python3 -I -B /opt/desire-supply/scripts/private_server_release_inputs.py measure \
  --input-root "$CANDIDATE_PRIVATE_INPUT_ROOT" \
  --bundle-name "$CANDIDATE_PRIVATE_BUNDLE_NAME"
```

成功结果固定包含 `status=PRIVATE_SERVER_RELEASE_INPUTS_MEASURED_NOT_AUTHORITY`、
`authority=NOT_AUTHORITY`、`execution_permitted=false`、`production_authorized=false`、
`file_count=68` 和候选 `tree_sha256`，不包含输入路径、bundle name 或材料。批准者必须把该摘要与
project、tag、镜像 ID、bind IP 和 subnet 一起写入独立发布记录；`measure` 结果本身不是批准。

从独立记录抄回全部 `APPROVED_*` 值后、紧邻 activator 之前，必须再执行只读 `verify`：

```bash
sudo /usr/bin/python3 -I -B /opt/desire-supply/scripts/private_server_release_inputs.py verify \
  --input-root "$APPROVED_PRIVATE_INPUT_ROOT" \
  --bundle-name "$APPROVED_PRIVATE_BUNDLE_NAME" \
  --expected-tree-sha256 "$APPROVED_PRIVATE_INPUT_TREE_SHA256"
```

成功状态必须为 `PRIVATE_SERVER_RELEASE_INPUTS_VERIFIED_NOT_AUTHORITY`，其余 authority/permission
字段仍保持上述关闭值。两项命令都只通过 anchored、no-follow descriptor 读取并验证输入树；不会
创建 staging、不会占用 project/attempt，也不调用 Docker、网络或子进程。摘要不匹配时必须停止并
人工比较，禁止把现场新算值回填为 `APPROVED_PRIVATE_INPUT_TREE_SHA256` 来继续。`verify` 与 activation
之间仍存在变更窗口，因此 activator 必须重新读取、验证并把同一批内存 bytes 写入永久 staging；
`verify` 不能旁路或替代该检查。两条命令都必须保留 `-B`；它禁止 Python 在受审 checkout 中写入
`.pyc` bytecode，不能为了“方便”省略。

下列变量必须逐项从同一份发布审批记录抄入，不能从未审核的 shell profile、`.env` 或 Docker
context 继承：

执行下列 `sudo` 之前，必须由受信任的主机安装/配置门禁从 `/opt` 开始，逐级验证 checkout
`/opt/desire-supply`、`scripts` 目录和 `activate_private_server_ingress.py`：每一级都必须为 root
所有、不可被 group/world 写入且不是 symlink，activator 本身还必须是不可被 group/world 写入的
普通文件。这个外部门禁发生在 Python 加载脚本之前，不能由待执行的 activator 自证，也不能只依赖
activator 运行后的摘要检查。

```bash
sudo /usr/bin/python3 -I -B /opt/desire-supply/scripts/activate_private_server_ingress.py \
  --project-name "$APPROVED_PRIVATE_PROJECT" \
  --env-file "$APPROVED_PRIVATE_INPUT_ROOT/compose.env" \
  --ipam-overlay "$APPROVED_PRIVATE_INPUT_ROOT/compose.ipam.yaml" \
  --bind-ip "$APPROVED_PRIVATE_BIND_IP" \
  --platform-image-id "$APPROVED_PLATFORM_IMAGE_ID" \
  --web-image-id "$APPROVED_WEB_IMAGE_ID" \
  --edge-image-id "$APPROVED_EDGE_IMAGE_ID" \
  --postgres-image-id "$APPROVED_POSTGRES_IMAGE_ID" \
  --input-tree-sha256 "$APPROVED_PRIVATE_INPUT_TREE_SHA256"
```

project 必须采用新的 `desire-private-ingress-…` 闭合集合名称。程序会先永久占用
`/var/lib/desire/private-ingress-attempts/<project>`；从这一刻起，无论成功还是失败，该 project
和 attempt 目录都不得删除、复用或重试。程序把关闭 input tree、Compose 源、identity template、
canonical resolved config、镜像锁和回执全部写入该目录，并在启动前完成以下核验：

attempt 祖先目录始终为 root `0700`。Compose 本机 file-backed config/secret 实际使用 bind mount，
不会兑现声明里的 `uid/gid/mode`；因此 staging 会把仅供审批比较的三项元数据保留为 `0600`，把
会挂载进非 root 容器的 exact 副本设为只读 `0444`。这些副本在主机上仍因 root `0700` 祖先不可
遍历，容器内 UID `10001` 则可读取；不得把 staged 文件搬到可遍历目录或放宽 attempt 祖先权限。

- 在同一进程中重新采集网卡与监听事实；
- 仅使用本机 Docker socket 和净化后的环境，确认 Compose 版本精确为 `5.3.1`；
- 先按四个受审 image ref 核对 image ID，再把 resolved config 中的镜像全部替换为 exact ID；
- 严格确认只有 Edge 发布 `127.0.0.1:443` 与目标私网 `:443`，六个管理服务仍为
  `INTERNAL_SANDBOX`、external participants 为 `false`，且命令、secret/config source、只读
  root filesystem、capability、依赖、healthcheck、网络、volume、project name 与每个 service 的
  Docker `local` 日志合同（`max-size=10m`、`max-file=3`、`compress=true`）都未漂移；
- 确认该 project label、十个确定 container name、四个确定 network name 和 PostgreSQL volume
  均不存在；随后再按 image ID 复核本机镜像。

只有上述检查全部通过时，程序才会对永久 resolved snapshot 发起唯一一次、禁止 build/pull 的
等待式启动。启动成功后，它还会对同一永久 resolved snapshot 取得 Compose 的十项权威 service
config hash，并只读抓取十个原始 container ID、四个原始 network ID、固定 volume name，以及每个
容器完整 `Config`/`HostConfig`/`Mounts` 安全投影的 canonical SHA-256；live config-hash label 必须与
权威输出逐项一致，才会原子写出关闭形状的 v2 成功回执。这里的安全投影只以摘要进入回执，不把
环境内容写入回执。不要手工拼装 Compose 启动命令，也不要直接消费原始 input tree 绕过该程序。

成功只输出：

```json
{"status":"PRIVATE_SERVER_INGRESS_ACTIVATED"}
```

启动调用之前的失败返回退出码 `78` 和稳定的 `PRIVATE_SERVER_INGRESS_ACTIVATION_INVALID`；这表示
没有进入唯一启动调用，但 attempt 仍已永久消耗。启动调用一旦发出，任何非零返回、超时、输出
异常或成功回执落盘失败都返回退出码 `75` 和
`PRIVATE_SERVER_INGRESS_PARTIAL_POSSIBLE`。后者必须按“入口可能已经上线”处理：立即在主机防火墙
和云安全组关闭本轮 TCP/443 来源规则，保全完整 attempt 目录和外部日志，只做只读状态检查并升级
人工处置；不得重试、清理、复用 project，亦不得依据错误文字假定容器没有创建。

激活后，受控客户端必须分别访问两个固定 hostname 并验证证书链，再执行合成角色旅程。任何客户
端解析到不同地址、证书警告、来源 allowlist 漂移、意外公网可达、镜像漂移或本 project 的 Edge
port map 超出两个审核过的 HTTPS bind，都必须停止本轮并保全证据；不能通过改成 `0.0.0.0`、关闭 TLS/OIDC 校验、
扩大防火墙范围或复用 v13 坐标继续。

### ORG_ADMIN 公开名称验收

合成角色旅程必须把“组织配置真正可用”与“角色仍不能越权”一起验收。使用预置的合成 `ORG_ADMIN` 登录同组织工作台，先确认 Organization、Membership 和邀请投影全部就绪，再执行：

1. 完成同账号 MFA，并在 `auth_time` 严格小于 10 分钟的窗口内操作；等于 10 分钟应显示 STEP_UP 恢复，不得当作成功。
2. 签发一枚合成组织邀请，在受控客户端以该一次性链接执行匿名 inspect，记录安全预览中的 Organization public name、Invitation ID/version/ETag 与 policy binding；token 只保留在本次受控进程内，不进入 shell history、截图、日志或证据正文。
3. 在公开名称表单输入一个与当前值不同的合成名称，确认其已 NFC、首尾无空白、含 1..160 Unicode code point 且无 `Cc`/`Cf`，并明确勾选“会立即影响未接受邀请的匿名预览”。写入必须带页面当前 Organization `If-Match`、独立 `Idempotency-Key`、same-origin CSRF 和恰为 `PUBLIC_NAME_CORRECTION` 的关闭 reason。
4. 对同一冻结请求做 exact replay，应逐字获得原 200 `OrganizationSummaryDto` 和 Organization ETag，不产生第二次版本增长。用新 key 再提交同名应得到 `409 INVALID_STATE_TRANSITION`，使用旧 ETag 提交另一名称应得到携当前 Organization ETag 的 412，并进入人工比较而非自动覆盖。
5. 再次 inspect 第 2 步的同一邀请链接；预览必须立即显示新 Organization public name，同时 Invitation ID、version、ETag、token binding 和 policy binding 与更名前一致。这证明预览使用 live join，而非通过重签发邀请刷新名称。
6. 以合成 `DEMAND_OWNER`、另一组织的 `ORG_ADMIN`、暂停成员或陈旧 Session 验证更名继续 fail closed；工作台不得提供 type/status/jurisdiction 或超出组织白名单的 role 配置入口。

名称验收的 audit/outbox 只核对受控 action/reason/version 与 `OrganizationPublicNameChanged {organization_id}`，不把旧/新名称复制到 audit、event、日志或 trace。完成角色旅程后按本页 manager 执行 `stop`，再使用受控 `recover` 验证名称持久；验证后再次 `stop` 并以只读 `status` 确认最终为 `STOPPED`。`recover` 明确不重跑 bootstrap；bootstrap v6 `APPLY`/`VERIFY` 不会把合法更正误判为 drift 或覆盖的证据，必须由发布前独立 PostgreSQL 门禁提供。仍只允许 `stop`/`recover`；不得为本验收使用 `down`、remove、recreate、build、pull 或重跑 one-shot。

## 已激活实例的只读状态、恢复与停止

只有 fresh activate 已成功写出完整 `desire-private-ingress-activation-v2` 回执的上述
**非 v13 INTERNAL_SANDBOX** project，才可使用
`scripts/manage_private_server_ingress.py`。它不是升级器、repair/migration 工具、一般生产运维入口，
也不接管旧回执、失败或 `PRIVATE_SERVER_INGRESS_PARTIAL_POSSIBLE` attempt。仍须由 root 通过同一受审
checkout 的 isolated Python 运行。调用前必须由受信任的主机安装/配置门禁（而不是由待执行脚本
自证）确认 `/opt` 到 checkout、`scripts` 和 manager 文件的每一级祖先均为 root 所有、不可被
group/world 写入、不是 symlink，manager 本身也是 root 所有、不可被 group/world 写入；否则 sudo
加载 Python 文件本身就已越过任何运行期检查。manager 还会显式要求 effective UID 为 0，但这不
替代上述外部门禁：

```bash
sudo /usr/bin/python3 -I -B /opt/desire-supply/scripts/manage_private_server_ingress.py \
  status --project-name "$APPROVED_PRIVATE_PROJECT"

sudo /usr/bin/python3 -I -B /opt/desire-supply/scripts/manage_private_server_ingress.py \
  recover --project-name "$APPROVED_PRIVATE_PROJECT"

sudo /usr/bin/python3 -I -B /opt/desire-supply/scripts/manage_private_server_ingress.py \
  stop --project-name "$APPROVED_PRIVATE_PROJECT"
```

三种动作都会先从永久 attempt 目录重新验证 root ownership、`0700/0600/0444` 权限、无 symlink、
关闭形状回执、input-tree、snapshot/source 摘要、四个镜像 ID 与 canonical resolved config；随后只用
净化环境、`/usr/bin/docker` 和本机 socket。manager 不执行 Compose plugin；Compose `5.3.1`、权威
config hash 和创建容器时的 Compose version/image labels 已由 v2 激活回执绑定。检查覆盖五个常驻服务、
五个已成功退出的 one-shot、四个 project network、PostgreSQL volume、Compose labels、容器镜像、
health 和两个受审 `:443` listener；同时枚举每个 network 与 PostgreSQL volume 的全部 container
consumer；为覆盖 stopped one-shot 和已停止常驻容器，它会先全局只读列出有限数量的全部 container
ID，再用固定 format 仅取得 ID、network 与 mount 投影，不读取其他容器的 Env/secret。未带 project
label 的额外挂载者也不能绕过。每个已绑定容器还必须保持激活回执中的完整安全投影摘要；因此
`docker update --restart always`、privileged/host namespace、命令/healthcheck 或额外 Docker socket
mount 漂移都会在修改前被拒绝，one-shot 的 restart policy 必须始终为 `no`。任一资源缺失、
label/image/network/volume/listener 漂移、one-shot
非零或状态不确定，都在任何计划内修改前 fail closed。

安全投影还精确比较每个已创建容器的 `HostConfig.LogConfig`，要求 driver 为 `local` 且 options
只有 `max-size=10m`、`max-file=3`、`compress=true`。它是每个新容器约 30 MiB 的本机有界
stdout/stderr 保留合同；`stop`/`recover` 保留同一容器日志，但不构成 Audit、集中日志、告警、
backup/PITR 或敏感数据擦除。不得通过 recreate 修复漂移，因为该 manager 只管理回执绑定的原容器。

listener 核验与激活 preflight 保持同一边界：目标私网 IP 与 `127.0.0.1` 必须随 Edge 状态精确出现
或消失，任何 IPv4/IPv6 wildcard `:443` 都拒绝；另一个不等于这两者的具体主机 IP 上由其他受控
服务持有的 `:443` 可以共存，本工具既不把它归属于该 project，也不宣称对整台主机的所有具体 IP
具有排他权。Edge 的 Docker live port map 仍只能是本 project 回执绑定的两项。

`status` 完全只读，只会给出固定的 `HEALTHY`、`STOPPED`、`RECOVERABLE` 或 `DEGRADED` 状态；这些
结果都不改变 G1/G2 NO-GO。`recover` 只处理已经存在且停止的五个常驻容器，严格按
DB → synthetic OIDC → Edge → API → Web，以预检时绑定的完整 container ID 执行更窄的
`docker container start`，并在进入下一服务前只读等待同一 ID 与 image ID 达到 healthy；它不会
调用 Compose `up`，因此不能创建或 recreate 缺失容器，也绝不重跑 migrate、taxonomy seed、
online credentials reconcile/verify 或 identity bootstrap。`stop` 严格按 Web → API → Edge →
synthetic OIDC → DB 停止已经核验并绑定到回执的容器 ID；不执行 `down`，不删除 container、network、
volume 或镜像。

任一 recover/stop 调用一旦发出而返回非零、超时、异常或最终复核不闭合，工具只返回退出码 `75`
与 `PRIVATE_SERVER_INGRESS_MANAGEMENT_PARTIAL_POSSIBLE`，停止后续动作并保全所有资源。此时先关闭
外部防火墙/安全组入口，保存 attempt 与主机日志，做只读 `status` 和人工升级；不得用 `down`、
remove、recreate、build、pull 或重跑 one-shot 来“修复”。`stop` 只停止容器，不替代撤销防火墙、
DNS、CA 或客户端访问授权。
