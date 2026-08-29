# INTERNAL_SANDBOX 合成 OIDC Provider

> 状态：`IMPLEMENTATION CONTRACT / SYNTHETIC ONLY / G1 NO-GO / G2 NO-GO`
> 目标：让 Docker INTERNAL_SANDBOX 通过正式 OIDC Authorization Code + PKCE 链路登录十个预置测试账号和一个未预置受邀身份
> 禁止：公开注册、任意 subject/email、真人身份、外网身份源、HTTP issuer、跳过 JWT/HTTPS 校验、发布到 OpenAI Sites

## 1. 固定信任边界

合成 IdP 不是生产身份提供商，也不是 persona 参数接口。它只在
`DESIRE_DEPLOYMENT_MODE=INTERNAL_SANDBOX` 且
`DESIRE_EXTERNAL_PARTICIPANTS_ENABLED=false` 时启动，并固定：

| 事实 | 固定值 |
| --- | --- |
| issuer | `https://identity.example.test` |
| client ID | `desire-internal-sandbox` |
| redirect URI | `https://pilot.example.test/v1/auth/oidc/callback` |
| response type | `code` |
| scope | `openid email` |
| PKCE | `S256`，必填 |
| ID token | `RS256`，固定合成测试 key ID |
| token endpoint auth | `client_secret_post` |

服务不提供 registration、dynamic client、password、reset、userinfo、管理 API、
任意 claims 或外部网络调用。Discovery 不能广告这些能力。

## 2. 十个 bootstrap 身份与一个 provider-only 受邀身份

| account code | provider class | `sub` | verified email |
| --- | --- | --- | --- |
| `access_admin_01` | bootstrap | `sandbox:access-admin-01` | `sandbox-access-admin-01@example.test` |
| `appeal_reviewer_01` | bootstrap | `sandbox:appeal-reviewer-01` | `sandbox-appeal-reviewer-01@example.test` |
| `creator_01` | bootstrap | `sandbox:creator-01` | `sandbox-creator-01@example.test` |
| `demand_owner_01` | bootstrap | `sandbox:demand-owner-01` | `sandbox-demand-owner-01@example.test` |
| `finance_operator_01` | bootstrap | `sandbox:finance-operator-01` | `sandbox-finance-operator-01@example.test` |
| `finance_operator_02` | bootstrap | `sandbox:finance-operator-02` | `sandbox-finance-operator-02@example.test` |
| `operations_reviewer_01` | bootstrap | `sandbox:operations-reviewer-01` | `sandbox-operations-reviewer-01@example.test` |
| `org_admin_01` | bootstrap | `sandbox:org-admin-01` | `sandbox-org-admin-01@example.test` |
| `trust_officer_01` | bootstrap | `sandbox:trust-officer-01` | `sandbox-trust-officer-01@example.test` |
| `trust_officer_02` | bootstrap | `sandbox:trust-officer-02` | `sandbox-trust-officer-02@example.test` |
| `invited_demand_owner_02` | provider-only | `sandbox:invited-demand-owner-02` | `sandbox-invited-demand-owner-02@example.test` |

这二十个固定 identity source 值与 identity bootstrap manifest generator 的正式 digest
domain 完全相同，只属于前十个 bootstrap 身份。第十一个
`invited_demand_owner_02` 只存在于合成 IdP：它不进入 identity bootstrap manifest、
角色期望或任何预授权。登录页精确显示这十个 bootstrap 按钮和一个 provider-only
受邀身份按钮；请求、表单或环境变量都不能提供第十二个 subject/email。选择账号不代表
真人认证，只用于内部工作流检查。

当前 bootstrap contract 保证 bootstrap-owned 最终有效权限互斥：`access_admin_01` 只有
`ACCESS_ADMIN`；`appeal_reviewer_01` 只有 `APPEAL_REVIEWER`；`creator_01` 只有
`CREATOR`；`demand_owner_01` 只有 `DEMAND_OWNER`；两个 finance 账号各自只有
`FINANCE_OPERATOR`；`operations_reviewer_01` 只有 `OPERATIONS_REVIEWER`；
`org_admin_01` 只有 `ORG_ADMIN`；两个 trust 账号各自只有 `TRUST_OFFICER`。
`org_admin_01` 与 `demand_owner_01` 共享 exact Organization ID，但拥有
不同 invitation、Membership 与 grant。非 Creator 账号保留的 CREATOR bootstrap
邀请/grant 仅是已撤销证据，不会产生 PERSONAL workspace；浏览器不能提交 role 来
改变这一事实。随后由正式 accepted invitation 产生的非 bootstrap-owned Membership 或
额外合法 role 不属于 bootstrap 漂移；bootstrap replay/verify 仍只严格核验其 own IDs。

## 3. 协议

公开 HTTPS 端点固定为：

```text
GET  https://identity.example.test/.well-known/openid-configuration
GET  https://identity.example.test/jwks
GET  https://identity.example.test/authorize
POST https://identity.example.test/authorize
POST https://identity.example.test/token
```

Authorization GET 只接受正式 API 生成的 exact client/redirect/state/nonce/S256
challenge。它创建一个短期、随机、内存 interaction handle；HTML 表单只回传该
handle 和十一个冻结 provider account code 之一，不回传可修改的
subject/email/redirect。

选择后生成短期一次性 authorization code，并以 `303` 返回原始 state。Token
POST 精确验证 client secret、client/redirect、一次性 code 和 PKCE verifier；code
在首次 token 尝试时消费。ID token 固定包含 exact issuer/audience/nonce、冻结
sub/email、`email_verified=true`、有界 `iat/exp/auth_time`、合成 `acr/amr` 和随机
session ID。重放、过期、未知账号、错误 PKCE 或字段扩展全部失败关闭。

为覆盖 IAM 的 recent-MFA 管理命令路径，fixture 固定签发
`acr=urn:desire:acr:synthetic-internal-sandbox:mfa` 与
`amr=["synthetic","mfa"]`。这里的 `mfa` 只是 INTERNAL_SANDBOX 测试声明：账号
选择器没有执行第二因子挑战，因此它不是、也绝不能被解释为真人 MFA、生产 step-up
或任何生产认证强度证明。生产部署不得信任该 issuer、固定测试签名 key 或这些合成
claims；真实 MFA 仍必须由受信生产 IdP 执行并证明。

## 4. HTTPS 与 Docker 接线

IdP 进程仅在 Compose 独立的 `oidc-backend` internal network 上监听明文
`0.0.0.0:8081`，不加入 `app` network、也不发布宿主端口；该网络只能包含 edge
和 IdP。它要求公开协议请求同时具有 exact
`Host: identity.example.test` 和由受控 edge 重建的
`X-Forwarded-Proto: https`；edge 必须删除来路的 `Forwarded` /
`X-Forwarded-Host` 并覆盖这两个 header。网络隔离与 header 校验共同阻止绕过
公开 HTTPS。`/health/live` 与 `/health/ready` 只接受容器自身发出的 exact
`Host: 127.0.0.1:8081`，且拒绝所有 forwarded headers，仅供 Compose 内部
healthcheck；identity HTTPS host 不能读取 health。

Edge 是唯一 TLS 终止点，并按 host 路由：

```text
pilot.example.test    → web:3000
identity.example.test → synthetic-oidc:8081
```

TLS certificate 必须覆盖两个 DNS SAN，私钥只挂载到 edge。浏览器必须显式信任
该 INTERNAL_SANDBOX CA；API 容器只读挂载同一 CA，并通过标准 CA file 使既有
`StdlibOidcJsonTransport` 验证 `identity.example.test`。不得改为 HTTP、关闭
certificate/hostname 校验或替换 `ClosedOidcProvider` / `PyJwtOidcTokenVerifier`。

浏览器所在主机将两个 `.example.test` 名称解析到 loopback；Compose `app` network
将 `identity.example.test` alias 指向 edge；edge 同时加入 `app` 与
`oidc-backend`，IdP 只加入后者。IdP 自身没有外网依赖。

API 与 IdP 必须挂载同一 OIDC client-secret file。IdP 只接受 `/run/secrets` 下的
direct regular file，内容为 32–4096 字节 printable ASCII、无换行/NUL。该 secret
不进入镜像、日志、HTML、discovery、JWKS 或错误正文。

### 4.1 Compose 精确服务契约

```text
service name: synthetic-oidc
command: python -m desire_platform.synthetic_oidc
internal listener: 0.0.0.0:8081
published ports: none
network: oidc-backend only (internal: true)
environment:
  DESIRE_DEPLOYMENT_MODE=INTERNAL_SANDBOX
  DESIRE_EXTERNAL_PARTICIPANTS_ENABLED=false
  DESIRE_SYNTHETIC_OIDC_CLIENT_SECRET_FILE=/run/secrets/key-oidc-client-secret-v1
secret mount:
  <bundle>/runtime-secrets/key-oidc-client-secret-v1
    -> /run/secrets/key-oidc-client-secret-v1:ro
healthcheck: GET http://127.0.0.1:8081/health/ready == 200
```

进程固定值不可用环境变量覆盖；出现任何 `DESIRE_SYNTHETIC_OIDC_*` 扩展键、非
INTERNAL_SANDBOX mode、external participants 开启、secret 位于根目录外/经
symlink/可被 group 或 other 写入时，进程启动失败关闭。容器应 `read_only`、
`cap_drop: [ALL]`、`no-new-privileges`，且不得挂载持久数据卷。

Edge 的 identity host upstream 必须是 `synthetic-oidc:8081`，并显式执行：

```text
Host := identity.example.test
X-Forwarded-Proto := https
delete Forwarded
delete X-Forwarded-Host
```

TLS 资产必须在启动 Compose 前离线生成；Caddy 不使用 `tls internal`，也不把其
data directory 挂载给 API：

```bash
python3 -B scripts/manage_internal_sandbox_tls.py create \
  --output-dir "$PWD/secrets/internal-sandbox-tls"
python3 -B scripts/manage_internal_sandbox_tls.py verify \
  --input-dir "$PWD/secrets/internal-sandbox-tls"
```

输出目录必须原先不存在，并且只包含：

```text
root-ca.pem          # 0444；只读挂 API，供浏览器管理员导入
edge-tls-chain.pem   # 0444；leaf + root，只读挂 edge
edge-tls-key.pem     # 0400；只读 secret，只挂 edge
```

Root CA signing key 只存在于生成器的受控 OpenSSL stdin/内存中，签发后覆零并丢弃，
永不写盘。API 只收到 `root-ca.pem`，不能看到 leaf key、chain 目录或 CA signing
key；edge 只收到公开 chain 和 leaf key。禁止把整个 TLS 目录或 Caddy data volume
挂进 API。

Compose 固定挂载与入口为：

```text
API:
  root-ca.pem -> /run/desire-tls/root-ca.pem (0444)
  SSL_CERT_FILE=/run/desire-tls/root-ca.pem
edge:
  edge-tls-chain.pem -> /run/desire-tls/edge-tls-chain.pem (0444)
  edge-tls-key.pem -> /run/secrets/edge-tls-key.pem (0400)
  tls /run/desire-tls/edge-tls-chain.pem /run/secrets/edge-tls-key.pem
  publish 127.0.0.1:443 -> 443 only
```

证书 leaf 的 DNS SAN 精确为 `identity.example.test` 与 `pilot.example.test`；验证器
检查 root/leaf chain、RSA-2048/SHA-256、serverAuth、CA/key usage、leaf key 匹配、
至少 24 小时剩余有效期、权限和无额外文件。浏览器安装的是公开
`root-ca.pem`，不是关闭证书或 hostname 警告。

无环启动依赖固定为 synthetic IdP healthy → edge healthy；API 同时等待 edge healthy
与 identity bootstrap 完成；Web 再等待 API healthy。Edge 不等待 Web，pilot upstream
在 Web ready 前不可用属于预期，不能以此放宽 API 的 OIDC HTTPS readiness。

## 5. 与正式平台的组合

API 部署配置保持：

```json
{
  "issuer": "https://identity.example.test",
  "client_id": "desire-internal-sandbox",
  "redirect_uri": "https://pilot.example.test/v1/auth/oidc/callback",
  "allowed_signing_algorithms": ["RS256"]
}
```

API 启动仍先通过 HTTPS discovery 与 JWKS readiness。Web 仍只调用
`POST /v1/auth/oidc/authorizations`，浏览器导航到返回的 HTTPS URL；callback BFF
仍只允许闭合 state/code/error 参数，并只接受 API 返回的同源相对 303。

身份 bootstrap 必须先用相同 issuer、OIDC subject digest key、recipient binding
key 生成并应用十个 bootstrap 账号的 digest-only manifest；不得把
`invited_demand_owner_02` 加入该 manifest。IdP 只为第十一个身份签发同样可验证的
subject/recipient binding，不创建 User、grant、邀请、角色或 Session；这些事实仍由
IAM 正式 bootstrap、邀请与 callback UoW 管理。受邀身份在正式邀请被接受前不得取得
DEMAND_OWNER 或任何其他预置权限。

## 6. 验收

1. Discovery/JWKS 的 issuer、origin、RS256、S256 与 capability 集合闭合；
2. 十个 bootstrap 账号和一个 provider-only 受邀身份均能完成 begin → chooser → code → token → 正式 JWT verify；
3. 十一个 provider 账号都固定得到 synthetic-only MFA ACR 与同时包含 `synthetic`、`mfa` 的 AMR；
4. 十个 bootstrap 账号生成的 subject/recipient digests 与 bootstrap generator 相同；受邀身份也生成正式可验证 binding，但在 bootstrap manifest 与预授权中完全缺席；
5. 第十二个账号、任意 subject/email、registration 路径、未知字段均不可表示；
6. code 一次性、过期和 PKCE 错误均失败关闭；
7. client secret、签名私有参数、code、nonce 不出现在 repr/log/JWKS/错误；
8. API 仍使用 HTTPS certificate/hostname 验证和 RS256 allowlist；
9. IdP 无外网调用、无持久真人数据、重启后旧 interaction/code 自然失效。

### 6.1 浏览器操作验收清单

下列检查只使用十一个冻结合成 provider 身份，不输入真人资料：

1. 在受控主机 hosts 中加入 exact 一行
   `127.0.0.1 pilot.example.test identity.example.test`；不要把这两个名字解析到局域网
   或公网地址。
2. 先运行 TLS `verify`，再由系统管理员把公开的
   `secrets/internal-sandbox-tls/root-ca.pem` 导入当前测试浏览器或操作系统的受信根；
   不导入 `edge-tls-key.pem`，也不点击“继续访问不安全站点”。
3. 用新建的临时浏览器 profile 访问 `https://pilot.example.test/`。地址栏必须无证书
   错误；页面必须持续显示 `INTERNAL_SANDBOX / G1 NO-GO / G2 NO-GO`，且没有注册入口。
4. 点击“通过 OIDC 登录”。浏览器必须导航到
   `https://identity.example.test/authorize?...`；scheme、host 和 path 任一不同都停止。
5. 页面必须只出现 `access_admin_01`、`appeal_reviewer_01`、`creator_01`、
   `demand_owner_01`、`finance_operator_01`、`finance_operator_02`、
   `operations_reviewer_01`、`org_admin_01`、`trust_officer_01` 与
   `trust_officer_02` 十个 bootstrap 按钮，以及 `invited_demand_owner_02` 一个
   provider-only 按钮，显示对应 `@example.test` 邮箱；不得显示或接受 subject/email
   输入框、密码、注册或第十二个账号。
6. 首轮选择 `creator_01`。浏览器应经过固定 callback
   `https://pilot.example.test/v1/auth/oidc/callback?code=…&state=…`，最终回到
   `https://pilot.example.test/app`；query 不得含 role、workspace、email 或 subject。
7. 工作区数据全部载入后，确认该账号只有 PERSONAL / CREATOR 工作区。再分别使用九个
   独立临时 profile 登录其余账号；`demand_owner_01` 与 `org_admin_01` 应在同一个
   Organization 中分别且只能得到 DEMAND_OWNER 与 ORG_ADMIN；两个 finance 账号各自只
   得到 PLATFORM / FINANCE_OPERATOR；其余账号分别只得到 PLATFORM / ACCESS_ADMIN、
   PLATFORM / APPEAL_REVIEWER、PLATFORM / OPERATIONS_REVIEWER 或 PLATFORM /
   TRUST_OFFICER。不要在浏览器存储或请求中手工增加
   role，也不能继承其他 profile 的 workspace selection。
8. 另用独立临时 profile 登录 `invited_demand_owner_02`：OIDC token 的 subject 与
   verified recipient binding 必须通过正式校验，但邀请被正式接受前不能看到
   DEMAND_OWNER 或任何其他角色工作区，也不能出现在十账号管理/bootstrap 清单中。
9. 负例：直接访问 `https://identity.example.test/register` 必须 404；修改 callback
   query、重放旧 callback、刷新已消费 code 或选择不存在账号必须失败关闭，且不创建新
   session/User/role。
10. 验收完成后关闭十一个临时浏览器 profile。Root CA 仅用于这个
    INTERNAL_SANDBOX；不把它安装到普通日常浏览器，不复制 leaf private key，不发布
    endpoint、截图凭据或资产到 Sites/公网。

命令行辅助检查应看到 HTTPS 验证成功而非 `-k` 绕过：

```bash
curl --fail --show-error \
  --cacert secrets/internal-sandbox-tls/root-ca.pem \
  https://identity.example.test/.well-known/openid-configuration
curl --fail --show-error \
  --cacert secrets/internal-sandbox-tls/root-ca.pem \
  https://identity.example.test/jwks
curl --fail --show-error \
  --cacert secrets/internal-sandbox-tls/root-ca.pem \
  https://pilot.example.test/
```

Discovery 必须只广告本文第 3 节的同源端点、RS256 与 S256；JWKS 必须只有 public
RSA 参数且无 `d/p/q/k` 等私有/对称材料。禁止给 curl 加 `-k` / `--insecure`。
