# 私有服务器真实 OIDC 静态配置

状态：`SNAPSHOT/PLAN GATE IMPLEMENTED · EXECUTION DISABLED · INACTIVE · INTERNAL_SANDBOX · EXTERNAL PARTICIPANTS FALSE`。

本页定义一份可审查、可解析、可生成不可变离线计划、但当前**不可执行激活**的真实 OIDC 私有服务器叠层。它证明最终
Compose 文档能够移除合成 IdP、让 API 与专用 egress guard 共用受控网络命名空间，并在部署时把十个已审核
真人身份预置到固定的十角色账号；它不批准服务器启动、真人试点、公开注册、生产使用或任何
G1/G2 决定。

未来唯一特权 broker、v3 provenance、v2 authorization scopes、global foreign discovery、guard probes、
readiness 与失败补偿的未实现设计见
[私有服务器真实 OIDC trusted executor](/architecture/private-server-real-oidc-trusted-executor.md)。该设计不
改变本页当前状态：仓库新增的 create-intent v1 只是关闭、纯离线、`NOT_AUTHORITY` 的请求解析合同，
不是 broker 或 create 授权；现有 v1 计划永久不可执行，当前 collector receipt 仍为 `NOT_AUTHORITY`。

`deploy/private-server-real-oidc.compose.yaml` 依赖 Docker Compose `5.3.1` 的 `!reset` 与
`!override` 合并语义。Compose profile 不是隔离控制。最终文档必须精确为十一个服务和四个网络：
没有 `synthetic-oidc`、没有 `oidc-backend`；`oidc-egress-guard` 连接非 internal 的
`oidc-egress`，API 通过 `network_mode: service:oidc-egress-guard` 共用它的 netns，Edge
只连接 `app` 与 `ingress`；独立 `matching-runtime` 只连接 `data`，不共享 API/OIDC 网络。
API 使用系统公共 CA 文件
`/etc/ssl/certs/ca-certificates.crt`，OIDC transport 显式使用空代理映射，不继承主机 proxy
环境。Edge 使用 `deploy/Caddyfile.real-oidc`，只提供健康端点和审核过的 pilot hostname，
不再代理 `identity.example.test`。

最终 resolved Compose 的全部十一个 service 还必须固定 Docker `local` 日志 driver 与精确 options
`max-size=10m`、`max-file=3`、`compress=true`；`oidc-egress-guard` 在 overlay 中显式声明，其他服务
继承/保留 base 合同。该静态关闭只说明未来新建容器的本机 stdout/stderr 名义上限约为 30 MiB，
不是 Audit、集中采集、告警、备份/PITR 或敏感数据擦除。

第三层 IPAM overlay 必须为最终的 `ingress`、`app`、`data`、`oidc-egress` 各提供一个互不重叠
的 RFC1918 `/24`，且宿主 RFC1918 HTTPS bind IP 不能落入任何容器 subnet，避免 Docker bridge
与宿主 LAN 路由重叠；不能继续声明 `oidc-backend`，不能复用其他 project 的 network name。真实
叠层负责删除 base 中的旧网络，validator 逐项绑定最终 name 为 `<project>_<logical-network>`。

## 当前不能执行激活的原因

仓库尚未取得真实 provider/client 值、目标服务器的真实证书与 DNS/防火墙证据。现在已有独立的
descriptor-bound stager、fresh preflight evidence schema、两阶段 activation/status/stop/rollback plan
builder，但所有 `execute` 入口都关闭。第一阶段只允许形成一次 `compose create --no-build --pull never`
零启动计划；第二阶段只在 canonical post-create evidence 证明五个不同的已审核 `.Image` ID 与精确容器
绑定后，形成 exact-container-ID start skeleton。baseline-only 只读 live inspect collector 已实现且不产生
authority；完整 security projection validator、每次 start 紧前的完整重查、guard 规则安装/deny probes/
Running+healthy gate、destination-firewall live enforcement 与 readiness runner 均未实现并作为 blocker
保留。不得把任一 `NOT_EXECUTED`/`NOT_AUTHORITY` 文件描述为启动授权。
`TRUSTED_CREATE_ONLY_PROTOCOL_UNIMPLEMENTED` 与 `RESOURCE_ORIGIN_ATTESTATION_UNIMPLEMENTED` 也必须逐字
保留：仅验证 create-intent 的 absent prestate 和 zero-start 目标，不能证明谁创建了资源，也不能授权
任何 Docker lifecycle 调用。

现有私服 activator/manager 固定
十一个服务、四个旧网络、合成 OIDC 依赖以及 `desire-private-ingress-*` 命名空间；真实 OIDC
validator 则只接受新的 `desire-real-oidc-*` 命名空间。不得把 real overlay 加到旧 activator
命令中，也不得手工执行 `docker compose up` 绕过这一边界。

Real Caddyfile 已固定一年期 HSTS 与最小 camera/geolocation/microphone Permissions-Policy。Web
运行时已对每个 HTML document 生成独立 32-byte nonce，覆盖不可信入站 CSP header，并在 Vinext
渲染前后绑定同一份 default-deny CSP；构建后响应测试已证明正常路由的全部脚本共用该 nonce，
策略不含 `unsafe-inline` / `unsafe-eval`，邀请 fragment 清理仍在可见 UI 前。但真实浏览器的
CSP violation、hydration、登录和邀请全流程验收尚未完成，因此该浏览器证据仍是 activation blocker。
框架默认 404 的内联错误样式会被上述策略拒绝，不纳入当前 activation 通过证据，也不是放宽
`style-src` 的理由。

现有 synthetic release-input preparer 也不能作为真实身份来源。实际 issuer、client ID、client
secret、十人的 subject/email 和 TLS 私钥必须由独立 real-OIDC source tree 提供，再由
`scripts/private_server_real_oidc_release_inputs.py` 完成 no-follow descriptor snapshot。stager 不输出
原始值；它使用 exact-SHA-pinned production runtime/secret parser 与 current release generator mapping，
把 runtime profile、key requirement、manifest entry/file name 和当前 53 个 runtime material 精确绑定，
并拒绝任何跨 53 个 bundle secret、三个 standalone secret 与 TLS private key 的内容复用，也拒绝十个
subject 或 verified email 的复用。

## Provider 兼容合同

候选 provider 必须同时满足：

- canonical HTTPS issuer 使用公共受信 CA、无末尾 `/`；discovery 精确位于
  `<issuer>/.well-known/openid-configuration`；
- issuer 与 pilot hostname 必须是审核过的 DNS name，不能是 IPv4/IPv6 literal；未来 live DNS 与
  egress firewall 还必须把 provider 解析结果绑定到审批记录，并拒绝 loopback、RFC1918、link-local、
  metadata endpoint 与审核 origin 以外的目的地址，同时防止 nip.io 类别名和 DNS rebinding 在后续
  discovery/token/JWKS 请求中改变目的安全域；deployment 的 `network_binding` 必须精确为
  `{mode: PINNED_PUBLIC_IP, pinned_public_ipv4: <reviewed canonical global IPv4>}`，该公网地址与宿主
  RFC1918 ingress bind 是两个独立事实，绝不能复用；
- discovery 的 issuer 必须逐字相等，authorization、token、JWKS 三个端点必须与 issuer
  同 origin，且不能依赖 HTTP redirect；
- Authorization Code + PKCE `S256`，scope `openid email`；token endpoint 接受当前 adapter
  使用的 form body client credential；
- ID token 只允许部署 bundle 审核过的 `ES256`/`RS256`，provider 不能宣告 `none`，并提供可用
  JWKS；
- claims 至少包含并通过 `iss`、`sub`、`aud`（多 audience 时还需 `azp`）、`nonce`、`iat`、
  `exp`、`auth_time`、`email`、`email_verified=true`、非空 `acr` 与非空 `amr`；`sid` 如存在也
  必须为非空字符串；
- provider 预登记的 redirect URI 必须精确为
  `https://<reviewed-pilot-hostname>/v1/auth/oidc/callback`，不能使用 wildcard、额外 query、端口或
  第二 hostname。

API 在监听前会主动读取 discovery 与 JWKS；公共 DNS、HTTPS、CA、endpoint origin、算法或 key
任一不闭合，API 必须保持启动失败。`oidc-egress` 只提供网络路径，不放宽协议校验。
Pinned transport 直接连接审核公网 IPv4，同时维持 issuer hostname 的 TLS SNI、证书 hostname 与 HTTP
Host 校验；这是 application-layer binding，不是宿主防火墙。当前 preflight 只允许证据把它记为
`pinned_oidc_transport: VERIFIED`，不得把 destination firewall live enforcement 记作 VERIFIED；后者仍是
`DESTINATION_FIREWALL_LIVE_ENFORCEMENT_UNIMPLEMENTED` execute blocker。

## 十账号预置与受邀入驻边界

普通未知身份的 `LOGIN` 与自助注册仍然关闭。除十账号预置身份外，真实 OIDC 只为一个精确、仍在
有效期内且状态为 `ISSUED` 的组织 `DEMAND_OWNER` 邀请开放匿名 `ENROLLMENT`。provider 必须同时
证明唯一 subject 和与邀请收件人完全一致的 verified email；匿名 `ORG_ADMIN`、初始管理员、过期、
撤销、陈旧版本、邮箱不匹配或已绑定其他用户的邀请都关闭失败。

回调只创建 `PENDING_ENROLLMENT` User、ExternalIdentity、已验证 ContactPoint 与邀请绑定 Session，
不创建 Membership 或 Role。只有在同一 Session 中完成政策确认并接受邀请后，User 才转为 `ACTIVE`
并只获得目标组织的 `DEMAND_OWNER`。若首次回调已经提交但浏览器未收到 Session，只有同一 invitation、
subject、digest key 与 verified contact 能恢复一个新 Session；不会复制 User/Identity，也不会借普通
登录绕过邀请证明。

十账号固定模板摘要仍必须为：

```text
b7f5326f75f17eb97cec77d92f963fe6af6755a26a1acf7af8944f33ee6ba942
```

固定账号精确为 `access_admin_01`、`appeal_reviewer_01`、`creator_01`、`demand_owner_01`、
`finance_operator_01`、`finance_operator_02`、`operations_reviewer_01`、`org_admin_01`、
`trust_officer_01`、`trust_officer_02`。它们必须来自十个不同的 provider user，每个 subject 与
verified email 都必须跨十账号唯一；不得让一个真人身份占用或切换多个账号。

模板独占十个 User ID、角色、授权和二十个 source filename；外部 source 只能提供每个账号的
provider subject 与 provider-verified email，且二十个文件必须齐全、无重复。生成器用在线运行时
相同的 active HMAC key/domain 计算 subject digest 与 email recipient binding digest，随后通过
现有 parse/apply/verify 闭环写入数据库。stdout 只包含 manifest digest 和结果，不得把 subject、
email、client secret、authorization code 或 token 写入命令行、环境、日志、证据或 manifest。

身份 source staging 的父目录必须由 validator 当前 effective UID 所有、权限关闭到 `0700`；
bind mount 根必须是同一 owner 的 `0555` 目录，二十个文件必须是同一 owner、单链接、普通文件、
精确 `0444`，每个 1–512 bytes。受保护父目录阻止其他宿主用户遍历，而 mount 后 UID `10001`
仍可从只读目录读取。不得把该目录放进源码 checkout、共享目录或可遍历父目录，也不得使用 symlink、
hardlink、额外文件或启动前可替换的 group/world-writable 路径。

identity-bootstrap 容器只得到三个 secret attachment：数据库管理员口令、OIDC subject digest key、
OIDC recipient-binding key。OIDC client secret、session key、业务 key 和其他数据库 capability 均不
进入这个一次性容器。

## 四层只读解析与关闭校验

以下是当前唯一支持的 real-OIDC 操作；它只解析与校验，不启动 Docker 资源。环境变量必须指向
**最终受审 staging tree**，不能指向 secret originals：同一个 current-effective-UID-owned staging
父目录必须精确 `0700`；其 bundle、identity 与 TLS 三个根目录及 bundle 中间目录必须精确 `0555`；
所有从 staging 挂载的 config、secret、证书、私钥与二十个 identity 文件必须是同一 owner、普通、
单链接、精确 `0444`。三个 standalone DB/seed secret 也是该 `0700` 父目录的直接 `0444` 子文件。
所有路径必须是 canonical absolute path，且不得位于源码 checkout。真实值必须来自独立审批记录，
不能复制下面的占位形式。

Bundle 的 `config/identity-bootstrap-template.json` 与 `config/Caddyfile.real-oidc` 也必须是 staged
`0444` 副本；validator 分别以固定 SHA-256 和 exact bytes 将它们绑定到仓库 canonical source，
不能直接把可变 checkout 文件挂进容器。

Secret originals 应保存在受保护 source tree 中并保持 `0600`。已实现的 stager 会在离线、不记录
原始值的流程中生成 exact-byte `0444` 副本，绑定 original→staged 摘要、device、inode、mode、size
与 anchored descriptor read；下面的路径只指 staged copies。不要把 `0444` 理解为宿主公开：共同
`0700` 父目录使其他宿主用户无法遍历，也不得把这些副本放在共享或可遍历目录下。

Source tree 根和全部中间目录必须为当前 effective UID 所有且精确 `0700`；根 inventory 精确为：

```text
bundle/config/{deployment.json,runtime-config.json,secret-manifest.json,
  online-credentials-deployment.json,online-credentials-runtime-config.json,
  online-credentials-secret-manifest.json,matching-deployment.json,
  matching-runtime-config.json,matching-secret-manifest.json,
  identity-bootstrap-template.json,Caddyfile.real-oidc}
bundle/runtime-secrets/<exact current manifest inventory>
identity-sources/<exact ten .subject + ten .email files>
tls/{edge-tls-chain.pem,edge-tls-key.pem}
db-password
taxonomy-workload
taxonomy-hmac
compose.ipam.yaml
```

该闭集当前精确为 91 个 source file；每个文件必须是同 owner、单链接、普通、精确 `0600`。
Attempts parent 必须是可信、canonical、
同 owner 的 `0700` 目录；空 attempt 根的 basename 必须逐字等于 project，例如
`/var/lib/desire/real-oidc-attempts/desire-real-oidc-pilot01`。stager 只运行
`/usr/bin/docker compose ... config --format json`，不连接 daemon lifecycle；它从 exact source bytes
生成 bundle/identity/TLS staging、仓库 Compose snapshots、canonical `resolved.compose.json` 与私有
`0400 snapshot-manifest.json`。manifest 包含 subject/email 等低熵值的 per-file digest，因此只能留在
该 `0700` attempt 内，不能上传、打印或复制进 plan；plan 只引用 manifest 的整体 SHA 与 inode。

`DESIRE_IMAGE_TAG` 只接受 runtime release 已验证的
`sha-<40commit>-(amd64|arm64)-r<run-id>-a<attempt>`；其中架构必须与服务器原生架构和已验证
bundle 相同，并与该 bundle 的 verified `release_id` 交叉核对。旧的 `real-oidc-*`、`local`、
任意 tag 或从路径猜出的值都会被 release-input stager 与 Compose validator 拒绝。

```bash
python3 -I -B scripts/private_server_real_oidc_release_inputs.py \
  --action stage \
  --input-root "/approved/0700/operator-source" \
  --attempt-root "/var/lib/desire/real-oidc-attempts/$DESIRE_REAL_OIDC_PROJECT_NAME" \
  --project "$DESIRE_REAL_OIDC_PROJECT_NAME" \
  --pilot-hostname "$DESIRE_REAL_OIDC_PILOT_HOSTNAME" \
  --oidc-issuer "$REVIEWED_REAL_OIDC_ISSUER" \
  --oidc-client-id "$REVIEWED_REAL_OIDC_CLIENT_ID" \
  --oidc-pinned-public-ipv4 "$REVIEWED_REAL_OIDC_PINNED_PUBLIC_IPV4" \
  --db-data-ipv4 "$REVIEWED_REAL_OIDC_DB_DATA_IPV4" \
  --image-tag "$DESIRE_IMAGE_TAG" \
  --ingress-ip "$DESIRE_PRIVATE_INGRESS_IP"
```

成功只输出 `{"status":"PRIVATE_SERVER_REAL_OIDC_INPUT_SNAPSHOT_READY"}`。默认/显式 `check` 只重开
attempt 并逐项核对 exact inventory、digest、inode 与 mode，不形成命令计划。

```bash
export DESIRE_REAL_OIDC_PROJECT_NAME="desire-real-oidc-<approved-new-name>"
export DESIRE_REAL_OIDC_PILOT_HOSTNAME="<approved-pilot-dns-name>"
export DESIRE_REAL_OIDC_BUNDLE_DIR="/approved/absolute/real-oidc-bundle"
export DESIRE_REAL_OIDC_IDENTITY_SOURCE_DIR="/approved/absolute/identity-sources"
export DESIRE_REAL_OIDC_TLS_DIR="/approved/absolute/tls"
export DESIRE_REAL_OIDC_DB_PASSWORD_FILE="/approved/absolute/db-password"
export DESIRE_REAL_OIDC_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE="/approved/absolute/taxonomy-workload"
export DESIRE_REAL_OIDC_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE="/approved/absolute/taxonomy-hmac"
export DESIRE_PRIVATE_INGRESS_IP="<approved-rfc1918-host-ip>"
export DESIRE_IMAGE_TAG="sha-<40commit>-<amd64-or-arm64>-r<run-id>-a<attempt>"
export REVIEWED_REAL_OIDC_ISSUER="https://<approved-provider-origin-and-path>"
export REVIEWED_REAL_OIDC_CLIENT_ID="<approved-client-id>"
export REVIEWED_REAL_OIDC_PINNED_PUBLIC_IPV4="<approved-canonical-global-ipv4>"
export REVIEWED_REAL_OIDC_DB_DATA_IPV4="<approved-unused-static-address-in-data-subnet>"
export REVIEWED_REAL_OIDC_IPAM_OVERLAY="/approved/absolute/compose.ipam.yaml"

set -o pipefail
docker compose \
  --project-name "$DESIRE_REAL_OIDC_PROJECT_NAME" \
  -f compose.yaml \
  -f deploy/private-server.compose.yaml \
  -f "$REVIEWED_REAL_OIDC_IPAM_OVERLAY" \
  -f deploy/private-server-real-oidc.compose.yaml \
  config --format json | \
python3 -I -B scripts/private_server_real_oidc_compose_contract.py \
  --project-name "$DESIRE_REAL_OIDC_PROJECT_NAME" \
  --pilot-hostname "$DESIRE_REAL_OIDC_PILOT_HOSTNAME" \
  --oidc-issuer "$REVIEWED_REAL_OIDC_ISSUER" \
  --oidc-client-id "$REVIEWED_REAL_OIDC_CLIENT_ID" \
  --oidc-pinned-public-ipv4 "$REVIEWED_REAL_OIDC_PINNED_PUBLIC_IPV4" \
  --db-data-ipv4 "$REVIEWED_REAL_OIDC_DB_DATA_IPV4" \
  --image-tag "$DESIRE_IMAGE_TAG" \
  --bundle-dir "$DESIRE_REAL_OIDC_BUNDLE_DIR" \
  --identity-source-dir "$DESIRE_REAL_OIDC_IDENTITY_SOURCE_DIR" \
  --tls-dir "$DESIRE_REAL_OIDC_TLS_DIR" \
  --ingress-ip "$DESIRE_PRIVATE_INGRESS_IP"
```

成功必须只输出：

```json
{"status":"PRIVATE_SERVER_REAL_OIDC_COMPOSE_VERIFIED"}
```

Python validator 自身失败只输出稳定 `PRIVATE_SERVER_REAL_OIDC_COMPOSE_INVALID`，不会回显输入值；
前置 `docker compose config` 的 interpolation/YAML 错误不属于该输出合同，可能输出变量名或路径，
因此任何 secret value 都不得放进环境值或命令参数。成功只证明静态 Compose、文件元数据和
deployment.json 绑定闭合，**不证明** provider 可达、client secret 正确、
证书私钥匹配、证书 SAN 包含 pilot hostname、DNS/防火墙安全、镜像 ID、数据库状态或 live readiness，
也不授权随后执行 `up`。

静态 validator 读取文件后到任何未来启动之间存在天然 TOCTOU 窗口；因此它永远不能直接成为
`up` 的前置授权。已实现 stager 会从 no-follow descriptor 读取生成不可变 attempt，并把 final
Compose bytes、全部 mount 的 inode/mode/digest 与五个镜像 reference 固定进私有 snapshot；activator
的默认 `check` 只重开并验证该 snapshot。任何未来 executor 仍须持有或重新验证这些 descriptor，且
只能从同一个 snapshot 完成唯一一次启动；不能把一次成功输出留存后用于稍后的可变路径。

本机 Docker Compose 的 file-backed config/secret 实际是 bind mount，不兑现 Compose 声明中的
`uid/gid/mode`。因此当前合同直接验证最终 `0444` staged copies；UID `10001` 的 Platform/Edge
容器在权限层面可读取它们，而共同 `0700` 父目录保护宿主机内容。不得把 `0600` originals 直接
绑定到 resolved JSON，也不得在 validator 之后改写路径或权限。这个权限闭合仍不授权 `up`：
snapshot closure 已实现，但 destination firewall live enforcement、guard 规则/deny-probe runner、真实
provider/DNS/TLS 与 live readiness runner 仍是独立 blocker。

## 离线 preflight 与计划管理

`deploy/private-server-real-oidc-broker-create-intent-v1.schema.json` 与
`scripts/private_server_real_oidc_trusted_executor_contracts.py` 冻结了未来 broker 唯一可接受的 create 请求
形状。parser 只接受 canonical、关闭字段的 bytes，递归永久拒绝旧 plan/authorization/stage/evidence
格式，并固定五个 image、十一个 absent container、四个 absent network、一个 absent PostgreSQL volume、
零 start 和 preserve-volume 约束。它不生成请求、不读取 snapshot、不访问文件/socket/process，也没有
执行入口；运维人员不能把通过 parser 当作批准或手工照此创建资源。

`scripts/preflight_private_server_real_oidc.py` 只接受 canonical absolute、当前 owner、单链接、精确
`0400`/`0600` 的 canonical JSON evidence file，并用 `O_NOFOLLOW` descriptor read 在读取前后核对
device/inode/mode/size/mtime/ctime。证据必须绑定 attempt manifest、resolved Compose、单独审核的
pinned provider IPv4、静态 DB data IPv4、egress projection digest、五个互不相同的本机 image ID，
以及 fresh resource query 的 exact command hash。fresh query 合同覆盖 project label、十一个默认
container name、四个 network name、一个 volume 与五个
image ID；当前工具只校验证据，不执行这些 query。

`scripts/activate_private_server_real_oidc.py` 默认/显式 `check` 只重开 snapshot，`--action execute`
无条件关闭。只有显式 `--action create-plan`、descriptor-protected `APPROVED` one-time authorization
和 `REVIEWED` fresh evidence，才会消费一个 UUIDv4 nonce（trusted `0700` claim root 中 `O_EXCL`、
`0400` receipt）并写出 create plan。其唯一 mutation command 形状是
`docker compose ... create --no-build --pull never`；它不含 `up`、`run --rm`、`start`，且明确零进程启动。

Create 后，`scripts/collect_private_server_real_oidc_post_create.py` 默认只生成 27 条 exact absolute
Docker 只读命令的 canonical collection plan，不访问 daemon。命令包含前后两次 project inventory
（集合必须一致）、十一个 container inspect、四个 network inspect、一个 volume inspect 与五个 image
inspect；不含 Compose、create、start、run、update 或 network connect/disconnect。只有显式
`--action collect` 才调用可注入 runner。每条命令只尝试一次，必须 exit 0、stderr 为空；stdout 必须
在固定上限内、strict UTF-8、无 NUL/重复 JSON key，inspect 只能是单一 JSON object。raw inspect
只在内存中使用，绝不落盘、回显或以 raw-object digest 形式复制到 receipt。

collector 的 v2 evidence 标记为 `COLLECTED_BASELINE_PROJECTION_VALIDATED_NOT_AUTHORITY`，在 private
`0700` parent 下以 `O_EXCL` 创建 `0400` 单链接文件，并在返回前 descriptor/lstat 重开核对 device、
inode、mode、owner、size 与 digest。该安全投影精确绑定 project 的十一个 service/container ID、每个
容器 `.Image`/`.Config.Image` 与五个 reviewed image ID、必需 Compose labels、所有 Compose staged
bind/volume mount、tmpfs、network/port/netns baseline、四个已创建 network object 与 PostgreSQL
volume。create 后、任何 start 前，每个 network inspect 的 `.Containers` 必须精确是 `{}`；
receipt 不声称尚不存在的 runtime membership 或 endpoint ID。container inspect
`NetworkSettings.Networks` 仅作为 desired config 验证：物理 network key、aliases 和
IPAM request 必须与 sealed Compose 精确一致，每个 `NetworkID` 必须是空字符串。API 因
`HostConfig.NetworkMode=container:<exact-guard-id>` 而 desired config 精确为空；guard 只声明
desired app/data/oidc-egress 与 `api` alias。DB static `IPAMConfig.IPv4Address`、guard 三个
reviewed egress environment value、API 的 sealed DB
extra-host、Edge 两个唯一 HTTPS bind，以及 project label inventory 下无额外 container/network/volume。

IPAM null/object 形状也是合同的一部分，不得互换：DB `data` 为 object 并带 exact
`172.29.25.10`；guard 的 app/data/oidc-egress 为 object，IPv4/IPv6 均为空；Edge
app/ingress、Web app 与其他普通 service 的 data membership 为 `null`。object 只允许
exact `IPv4Address`/`IPv6Address`，静态 IPv6、gateway 或额外字段均 fail closed。
同一次 exact image inspect 还提供 `Cmd`/`Entrypoint`/`User`/`WorkingDir`/`StopSignal`
的 image defaults（未设 `StopSignal` 时按 Moby `omitempty` 形状规范为空字符串）以及
`Config.ExposedPorts`/`Config.Volumes`。collector 按 sealed Compose 的 explicit override /
image-inherited 语义在内存中逐项比较 container `Config`。审核合同精确要求 Platform
`8000/tcp`、Web `3000/tcp`、Edge `443/tcp` + `8080/tcp`、PostgreSQL `5432/tcp`、
guard 无 exposed port，且只允许 PostgreSQL image volume target `/var/lib/postgresql`。container
`Config.ExposedPorts` 必须精确等于 image exposed ports 与 sealed Compose published target 的并集；
`Config.Volumes` 必须精确等于 image volume targets。`HostConfig.PortBindings` 只能是
reviewed published subset（当前仅 Edge `443/tcp`），image-only `8080/tcp` 不得出现在其中。
当前目标 Moby 的 never-started container 必须精确呈现
`NetworkSettings.Ports={}`；`null` 或 exposed-port-to-null map 都 fail closed。receipt 只写安全
port list、count 和 match 布尔，image volume 只写 count/显式覆盖布尔，不写 target path、
host path 或 raw inspect digest。`HostConfig` 还严格比较 CapAdd/CapDrop、规范化后的
no-new-privileges、RestartPolicy、
Sysctls、Init、ExtraHosts、Devices/DeviceRequests、supplementary groups、pid/ipc/uts 私有模式与默认
userns mode。

同次 image inspect 的 `Config.Env` 与 sealed Compose 5.3.1 `environment` 现在按当前 Linux Moby
create merge 语义形成精确 effective map：Compose 同名 key 覆盖 image default，其余 image key 继承；
container `Config.Env` 只允许该 exact map，数组顺序不影响比较。image、Compose 和 container 三层都拒绝
重复 key、NUL、缺少 `=`、非 `[A-Za-z_][A-Za-z0-9_]*` key，以及大小写任意组合的
`http_proxy`/`https_proxy`/`ftp_proxy`/`no_proxy`/`all_proxy`。receipt 只保留 image/Compose/
override/inherited/effective 计数、来源和 exact-match/proxy-absent 布尔；不保存 Env key/value、整图 digest、
pilot hostname、URL 或 healthcheck command。

Healthcheck 同样使用 same-inspect image default，并对 `Test/Interval/Timeout/Retries/StartPeriod/
StartInterval` 六字段执行 Moby 的逐字段零值继承，不把显式 Compose healthcheck 错当成整对象替换。当前
resolved Compose 的五个 probe（DB、guard、API、Web、Edge）完整 `Test` argv、1/3/5/10/15/20 秒
timing 与 retries 都是关闭 allowlist；inspect 中零值字段必须按 `omitempty` 缺失，任何未知字段、命令或
数字漂移均 fail closed。receipt 只写整体来源、六字段各自的 Compose/image/unset 来源与 match 布尔。
`Config.StopTimeout` 还要求 DB 精确 `60`、API 精确 `20`；其他八个服务按当前 `omitempty` inspect
形状不得出现该字段，显式 `null` 也不接受；image inspect 也不得出现这个不参与 Moby image-default
merge 的 create-time 字段。receipt 只写 present/source/match，不写 probe 文本。

每个 image `VOLUME` target 还必须被 sealed Compose 的同目标 bind/volume/tmpfs 显式覆盖。
PostgreSQL 18.4 的 parent `/var/lib/postgresql` 由 exact legacy `HostConfig.Tmpfs` 覆盖，named
volume 仍只挂到 child `/var/lib/postgresql/data`；这阻止 Engine 为 image parent `VOLUME`
生成匿名 volume。当前 Moby `GetMountPoints` 不把 legacy `HostConfig.Tmpfs` 反射到
top-level `.Mounts`，所以 collector 分别精确比较 `HostConfig.Tmpfs` 与只含 sealed
bind/volume 的 `.Mounts`；不接受未经 target-version fixture 证明的“可选 tmpfs mount”宽松分支。
top-level `.Mounts` 的集合按 destination 比较、顺序无关，但每个对象的字段集合和值都关闭：staged
config/secret/identity bind 只能含 exact `Type/Source/Destination/Mode/RW/Propagation`，其中
`Mode=""`、`RW=false`、`Propagation=rprivate`，不得注入 `Name`、`Driver` 或其他字段；DB named volume
还必须精确含物理 volume `Name`、`Driver=local`、`Mode=rw`、`RW=true`、空 `Propagation`，其
`Source` 必须与同一次 exact volume inspect 中只在内存读取的 `Mountpoint` 相等。

create transport 同样单独关闭。staged config 在 `HostConfig.Mounts` 中只能是四字段 bind object；secret
和 `create_host_path:false` identity bind 必须在相同四字段之外精确带空 `BindOptions={}`，不得出现
advanced bind options、`Consistency` 或其他 mount option。DB named volume 只允许 sole legacy
`HostConfig.Binds=["<physical-volume>:/var/lib/postgresql/data:rw"]`；其他服务的 `Binds` 必须精确为
`null`，没有 Mount-API bind 的服务不得渲染 `HostConfig.Mounts`。receipt 只保存各层 exact-match
布尔和计数，不保存 bind source、legacy bind string 或 volume `Mountpoint`。
只有 guard 可含 `NET_ADMIN`；除明确的 PostgreSQL entrypoint 兼容性例外外，其余九个服务必须
`cap_drop=ALL` 且启用 no-new-privileges。该 DB 例外要求 live 值精确为空，不允许借“例外”增加能力；
最小化 DB capabilities 必须另有目标 Engine 上的真实初始化/升级/重启证据，不能靠静态推断。
receipt 只
保存安全投影和 purpose-separated digest，不含 Env 文本、bind source、volume Mountpoint 或 raw
inspect。通过实际采集只移除 `POST_CREATE_LIVE_INSPECT_COLLECTOR_UNIMPLEMENTED`；它仍保留
`POST_CREATE_SECURITY_PROJECTION_RULE_VALIDATOR_UNIMPLEMENTED`，因为
`CgroupnsMode`/Cgroup/DeviceCgroupRules、resource/Ulimit/OOM、Runtime/
LogConfig/DNS/Links/VolumesFrom/masked-readonly-path、权威 config-hash、network
driver option/gateway/启动后 actual endpoint、foreign volume consumer 与所有 guard netns consumer 尚未闭合。
这里的 `LogConfig` blocker 特指 post-create **live inspect 投影与目标 Engine fixture** 尚未实现；上文
resolved Compose 的 exact static logging 合同已经闭合，二者不得混写。静态 YAML/config 通过不能
证明未来 container 的 live `HostConfig.LogConfig`，也不能移除该 execute blocker。
当前 offline fixture 覆盖上述五组 image/container metadata、PostgreSQL parent VOLUME、
never-started empty port map 与 `StopSignal` 缺失形状，但尚无目标 Engine captured fixture。目标
fixture 仍必须证明 image/container effective `Config.Env`、六字段 `Config.Healthcheck` merge、DB/API
`Config.StopTimeout` 与其他服务的 omitempty 缺失形状，以及 `Config.ExposedPorts`/`Config.Volumes`、
`WorkingDir`/`StopSignal`、精确 `HostConfig.PortBindings`/`HostConfig.Tmpfs`、不含 legacy tmpfs 的
top-level `.Mounts`、config/secret/identity 的 exact `HostConfig.Mounts` null/empty-option shape、
DB sole legacy `HostConfig.Binds`、volume inspect `Mountpoint` 与 named-volume Source 的同次绑定，
以及 never-started `NetworkSettings.Ports={}`。它还必须证明四个 network inspect
`.Containers={}`、container desired network keys/aliases、exact IPAM null/object matrix 和所有
`NetworkID=""`。DNSNames 可选渲染、tmpfs option 与启动后 actual network membership 仍属于
上述 security projection blocker，不能据此放宽或启动。

目标 Engine 兼容证据还必须绑定 Server/API version、OS/Arch 与 daemon profile；例如 `Init=null` 是
daemon-default，不等价于显式 false，UsernsMode 也不能把未由目标 Moby 版本证明的 `private` 当成默认值。
精确 pinned Caddy 2.10.2 Alpine source image 没有 `VOLUME`/`STOPSIGNAL`，但其 image config
含 80/tcp、443/tcp、443/udp、2019/tcp 等额外 expose。Edge Dockerfile 先在 pinned Caddy
source stage 完成 uid/gid、capability removal 和目录准备，再把完整 filesystem 复制到
`FROM scratch AS edge-runtime`，因而不继承 source image config。final stage 的静态合同是关闭
allowlist：显式 Alpine PATH（Compose healthcheck 需要 `wget`）、XDG env、`WORKDIR /srv`、
`USER 10001:10001`、仅 `EXPOSE 443 8080` 以及绝对路径 `/usr/bin/caddy` CMD；不宣告
`VOLUME`/`ENTRYPOINT`/`STOPSIGNAL`。静态测试会对任何新增元数据或回退到继承 base
fail closed。目标 Engine fixture 仍须确认 build 后 edge image 的精确 config 与健康检查/
graceful-stop 行为；在此之前不产生 start authority。

v2 receipt 的 canonical shape、digest 与 file seal 只证明“这份私有文件内部一致且未被普通链接替换”，
不证明 runner provenance；同 owner 能读取 snapshot/create plan 时，仍可能离线构造一份内部一致的 v2。
因此 `check` 只返回 `NOT_AUTHORITY`，并逐字保留
`POST_CREATE_COLLECTOR_PROVENANCE_UNIMPLEMENTED`、`DOCKER_SOCKET_EXCLUSIVE_BROKER_UNIMPLEMENTED`
与 `EXECUTION_AUTHORIZATION_V2_UNIMPLEMENTED`。未来 executor 必须增加独立可信的 collector
claim/transcript 签名或 MAC，并由 exclusive Docker-socket broker 把最终重查与 exact-ID start 放在同一
锁定流程；不能把 receipt 自述的 `command_attempts` 当作 attestation，也不能把旧 v1 authorization
当成可执行授权。collector 在内存中要求 Compose-generated labels 为关闭集合，逐项匹配 image ID、
version、depends_on 与两个 path labels；同次 image inspect 的非 Compose labels 必须原样继承且 image
不得预占 Compose namespace。receipt 只写 `path_labels_match` / `image_labels_match` 与
`config_hash_shape_valid` 布尔，不写 path、image label、self-reported config-hash 值或其 digest；完整
config-hash 必须由 pre-create pinned `docker compose config --hash '*'` 映射提供，仍由 security
projection blocker 兜底。volume Options 必须为 `null/{}`，也不写 raw options digest。

旧 evidence 或一次 v2 observation 都不是持续授权。当前中间 inspect 按审核名称执行，前后只复核
project-label inventory；可恢复的 name/config race、foreign volume consumer 与无 project label 的 guard
netns sharer不在本次 baseline provenance 内。Docker API 也可在 create 后改变 network、mount-adjacent
configuration 或其他 project object，因此未来
runner 必须在**每个 exact-ID start 紧前**重新 inspect 全部容器、镜像、labels、mount、network、port、
netns、四个 network、volume 与 project inventory，并逐字匹配 sealed evidence；任何差异先于 start
fail closed。

只有另一个 `START_CREATED_CONTAINERS` one-time authorization 才能形成 `--action start-plan`。该步骤
把 create plan、post-create evidence、start authorization、start plan 和 nonce claim 复制到 exclusive
lock + descriptor/inode/digest/mode-sealed 的私有 execution stage；stage 仍标记
`SEALED_NOT_EXECUTED`。legacy start-authorization v1、start plan v1 与 execution-stage v1 都必须显式写
`authority=NOT_AUTHORITY`、`legacy_execution_accepted=false`；只有未来独立定义并验证的 v2 execution
authorization 才可能解除 `EXECUTION_AUTHORIZATION_V2_UNIMPLEMENTED`，不能升级解释旧文件。
start skeleton 禁止后续 Compose mutation，只能引用精确 container ID，顺序为
`guard → DB → migrate(start/wait/exit 0) → taxonomy-seed(start/wait/exit 0) → reconcile(start/wait/exit 0)
→ verify(start/wait/exit 0) → identity-bootstrap(start/wait/exit 0) → API → Web → Edge`。仅有顺序不够：
guard start 后、DB 或任何 dependent start 前，未来 runner 还必须重新确认该 exact guard ID 的
`State.Running=true`、`State.Health.Status=healthy`、已安装规则与 egress projection 完全一致并通过 deny
probes。上述 baseline collector 已实现，但完整 security projection、pre-start reinspection、guard gate
与所有 readiness runner 尚未实现，所以第二阶段仍然 `execution.permitted=false`。v2 START plan 必须
逐字公开至少 `TRUSTED_CREATE_ONLY_PROTOCOL_UNIMPLEMENTED`、
`RESOURCE_ORIGIN_ATTESTATION_UNIMPLEMENTED`、
`POST_CREATE_COLLECTOR_PROVENANCE_UNIMPLEMENTED`、
`DOCKER_SOCKET_EXCLUSIVE_BROKER_UNIMPLEMENTED`、
`EXECUTION_AUTHORIZATION_V2_UNIMPLEMENTED`、
`POST_CREATE_SECURITY_PROJECTION_RULE_VALIDATOR_UNIMPLEMENTED`、
`PRE_START_FULL_REINSPECTION_RUNNER_UNIMPLEMENTED`、
`GUARD_RUNNING_HEALTHY_RULESET_GATE_RUNNER_UNIMPLEMENTED`、
`GUARD_RULESET_INSTALL_AND_DENY_PROBES_UNIMPLEMENTED`、
`DESTINATION_FIREWALL_LIVE_ENFORCEMENT_UNIMPLEMENTED` 与
`LIVE_READINESS_RUNNER_UNIMPLEMENTED`，不能用一个泛化摘要隐藏未实现步骤。

`scripts/manage_private_server_real_oidc.py` 默认 `status-plan` 只形成 exact read-only inspect command
形状，既不调用 Docker 也不需要 mutation authorization；`check` 仍只重开 snapshot。显式 `stop-plan`
与 `rollback-plan` 需要另外绑定精确 container/network/volume ID 的 reviewed evidence 和 one-time
authorization，且只写 `NOT_EXECUTED` 计划。证据与计划必须包含精确 guard container ID，并绑定 DB
static IP 与 egress projection。STOP/ROLLBACK 还必须提供 canonical、同 owner、精确 `0700` 的 nonce
claim root；manager 会在写计划前用 `O_EXCL` 创建 `0400` claim，将 UUIDv4 nonce 绑定到 operation、
authorization/evidence digest 与 plan digest，同一 nonce 不能在 STOP、ROLLBACK 或重试间复用。当前
rollback 语义只是 preserve-volume emergency stop skeleton，
不是旧版本恢复；所有 manager 的 `execute` 入口同样关闭。

## 未来 live 验收必须满足的顺序

只有新的 real-OIDC activator、回执格式和人工批准完成后，未来 live 门禁才可以执行。它至少必须：

1. 使用从未创建过的 project 与全新 `postgres-data` volume；禁止接管、复制或挂载任何 synthetic、
   v13/v14 drill 或既有私服 volume；失败或回滚时也不得删除或复用该 volume；
2. 先启动 exact guard container ID，确认 Running、healthy、规则 projection 与 deny probes；再按
   `db → migrate → taxonomy-seed → online-credentials-reconcile →
   online-credentials-verify → identity-bootstrap` 完成一次性初始化；identity apply 与 verify 都成功
   后，API 才可继续；
3. Edge 只暴露审核过的 loopback 与 RFC1918 HTTPS bind；API 先完成真实 discovery/JWKS readiness，
   随后 `matching-runtime` 与 Web 健康，Edge 最后暴露入口；最终精确十一服务、四网络，只有 guard
   连接 `oidc-egress`，API 与它共用 netns，`matching-runtime` 仅连接 `data`；
4. 让十个不同的 provider 用户分别登录并核对十个固定角色工作台；不能用一个真人身份切换角色，
   不能直接修改 digest 或数据库绕过登录；
5. 使用一个明确未预置的 provider 测试用户完成授权回调，必须得到关闭式拒绝：不创建 User、
   ExternalIdentity、Session、邀请或 enrollment 事实，不发 session cookie；随后重新核对十账号数量
   未变化；
6. 验证 restart 后十账号绑定与角色事实保持、旧未授权用户仍被拒绝，并完成新 volume 的独立
   backup/restore/PITR 证据。

当前仓库只有不可执行的 snapshot/preflight/plan builder 与不产生 authority 的只读 baseline collector，
没有 start、readiness、guard live-rule 或 deny-probe runner；因此 mutation 步骤仍是 server-side live
blockers，而不是可在本页手工执行的命令。

## 回滚要求

未来 real-OIDC 激活方案必须在启动前固定回滚记录。异常时先撤销外部 TCP/443 allowlist，再保全
resolved Compose、输入摘要、容器/网络/volume ID 和 provider 事件。现有 real manager 只会形成
`Edge → Web → API → OIDC egress guard → DB` 的 `NOT_EXECUTED` 停止 skeleton，使新流量最先被阻断，
并在 API 退出后才停止其共享 netns guard；它不会运行命令，
`ROLLBACK` 也只表示 preserve-volume emergency stop skeleton，不能声称恢复旧版本。未来 runner 不得
调用现有 v13 manager，不得 `down -v`、删除新 volume、重跑 identity bootstrap、复用 project 或用
synthetic overlay 替换运行中配置。随后在 provider 侧撤销该 exact client secret/redirect、回滚 DNS
与证书，并保持数据库和原始身份 source 封存，直到人工完成取证与数据处置决定。
