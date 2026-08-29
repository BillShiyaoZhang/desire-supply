# ADR-0003：OIDC、BFF 会话与协议级并发例外

> 状态：已接受
>
> 日期：2026-08-07
>
> 决策驱动：受邀登录必须可撤销、不可把浏览器暴露给长期 bearer token，并且要明确 OIDC callback 与平台通用幂等/乐观并发规则的边界。

## 背景

[目标平台领域模型](/architecture/platform-domain-model.md)要求所有外部写命令携带 `Idempotency-Key` 和期望版本，使用命令收据与乐观并发阻止重放和覆盖。这适用于平台业务命令，但以下身份协议入口天然不同：

- OIDC callback 由身份供应商重定向浏览器，不能可靠携带平台自定义请求头；
- 未认证用户尚无 actor 或聚合版本；
- AccessInvitation inspect 为了避免 secret 出现在 URL，需要使用 POST 承载一个只读查询；
- session logout/revoke 是单调安全动作，不应因 stale ETag 阻止撤销；
- 创建新 Organization 或第一个 AccessInvitation 时不存在旧聚合版本。

若不显式记录例外，实现者可能关闭全局保护，也可能强行要求浏览器/供应商无法提供的 header，从而产生不安全的旁路。

## 决策

### 登录协议采用 OIDC Authorization Code + PKCE

首个身份切片使用 OIDC Authorization Code Flow 与 PKCE S256，通过版本化 `IdentityProviderPort` 隔离供应商。平台不保存本地密码，不用 invitation magic link 单独替代认证，也不让浏览器 JavaScript 持久保存 provider access token。

实现顺序固定为：

1. 确定性本地 fake 契约；
2. provider adapter 契约；
3. 真实供应商沙箱验证；
4. 经 ADR-0001 的法律、安全、隐私和运营门禁后才允许真实启用。

fake 必须执行与真实 adapter 相同的 issuer、audience、redirect URI、state、nonce、PKCE、code 单次使用、时间窗、`acr`、`amr` 和 verified recipient binding 校验，不能成为更宽松的测试后门。

OIDC 认证只证明一个 provider subject 的控制权和声明的认证强度，不等于法定身份/KYC 验证。`IdentityVerification` 使用独立端口和状态，后续按交易风险启用。

### 浏览器使用服务端 BFF session

OIDC callback 成功后，BFF 创建服务端 Session，并向浏览器设置高熵 opaque handle。数据库只保存 handle 的 keyed digest，不保存可直接重放的 cookie 值。cookie 使用：

```text
Name: __Host-ds_session
Secure: true
HttpOnly: true
SameSite: Lax
Path: /
Domain: omitted
```

OIDC begin 另签发仅绑定单个 AuthTransaction 的临时 `__Host-ds_oidc` cookie：至少256 bit、`Secure; HttpOnly; SameSite=Lax; Path=/`、省略Domain、最大10分钟。数据库只保存它的versioned/domain-separated keyed digest与key ID。callback必须同时验证query state与该cookie；state本身不是browser binding。新begin覆盖旧临时cookie，所以旧tab不能仅凭旧state完成。terminal callback清除它；raw state/browser secret、authorization URL和provider code均不进入日志、audit或持久safe DTO。OpenAPI必须把begin的Set-Cookie和callback的required cookie输入标为sensitive/redact。

Session 只保存 user_id、auth_time、认证强度、生命周期、撤销、轮换和一次性 invitation verification 事实；不保存具有事实来源意义的角色、Membership、政策接受或 active organization 快照。每次业务授权读取当前状态。普通登录 Session 不携带 invitation verification，因此不能用于接受邀请。

所有同源不安全方法还必须校验 Origin 和与 Session 绑定的 synchronizer CSRF token。token 按 ADR-0004 从 raw Session handle、持久化 salt 与版本化 key 确定性派生，并以持久化 digest 校验，使 `/auth/session` 可返回当前 token 而不保存 raw secret。OIDC callback 不使用普通 CSRF token，而由一次性 AuthTransaction 的 state、nonce、PKCE、发起浏览器绑定与精确 redirect URI 保护。CORS 对凭据请求使用显式 origin allowlist，不允许 `*`。

登录完成、邀请接受导致权限提升、账户恢复和高风险 step-up 后必须按 [ADR-0004](/decisions/0004-iam-onboarding-persistence-and-postgres.md) 的 Session family/generation 协议轮换 Session handle 与 CSRF secret。检测到旧 handle 重放时撤销该 session family 并生成安全审计。

Invitation accept 的事务已提交但 `Set-Cookie` 丢失时不为 predecessor 设置宽限，也不从 receipt 重建 raw successor handle/CSRF。旧 cookie 仍触发 family 撤销；用户普通 OIDC 重新登录后，同一 User 用同 command key/hash 重试，只有已存在的 COMPLETED receipt 可在 onboarding guard 前重放安全 JSON body。receipt 不存在时仍必须重新完成 exact Invitation step-up。

### 账号发现与恢复

新 provider subject 只有在 AuthTransaction 绑定了仍可用的 AccessInvitation 时才能创建 `PENDING_ENROLLMENT` User；未知用户的普通登录返回统一失败，不创建账户。每一次接受邀请（既有 User 也包括在内）都必须先执行绑定该 exact Invitation 的 ENROLLMENT/STEP_UP AuthTransaction；callback 产出的 Session 必须同时记录精确的 `verified_contact_point_id` 与 `verified_for_invitation_id`。普通 LOGIN、另一 Invitation 或另一 contact row 的验证不可重放。平台不得根据相同邮箱自动连接两个 ExternalIdentity，也不得把 invitation recipient matching 当成账号恢复。

ACTIVE User 的普通 LOGIN 可建立正常 Session；ACTIVE User 的 invitation STEP_UP 只在 expected_user、exact Invitation 和 exact contact 都匹配时建立一次性绑定 Session。PENDING_ENROLLMENT User 只能获得对应 Invitation 的受限 onboarding Session。SUSPENDED/CLOSED User 即使 provider 验证成功也不得建立可用 Session；SUSPENDED 只返回统一受限结果，CLOSED 永远拒绝。

首切片的凭据恢复和 MFA enrollment 由 IdP 负责；平台通过 `acr`、`amr` 和 `auth_time` 执行近期 MFA/step-up 要求。身份绑定增加、移除和跨 provider 恢复需要独立设计，不在本 ADR 中暗自实现。

### 通用并发规则的明确映射

通用规则仍是：业务写命令携带 `Idempotency-Key`；更新现有业务聚合同时携带 `If-Match`；相同 key/相同 payload 重放原结果，不同 payload 返回 409；旧版本返回 412。只有下表列出的协议入口例外：

| 入口 | `Idempotency-Key` | `If-Match` | 等价或补偿控制 |
| --- | --- | --- | --- |
| `BeginOidcAuthorization` | 不要求 | 不适用 | 高熵一次性 state、nonce、PKCE verifier；accept 前必须验证 token 并把 exact Invitation/contact/expected user 绑定到 AuthTransaction |
| OIDC callback | 不要求 | 不适用 | state/browser 精确匹配、code 单次使用、AuthTransaction compare-and-consume、provider issuer/audience/时间窗及 exact contact tuple |
| `POST /access-invitations/inspect` | 不要求 | 不适用 | 语义只读、零持久化、token-in-body、限速、`Cache-Control: no-store` |
| 创建新 Organization | 必须 | 不适用 | actor/command/client_reference 唯一收据；不存在可比较的旧聚合 |
| 创建组织子资源 AccessInvitation | 必须 | 必须匹配 Organization | 创建结果由 Organization 版本和唯一约束保护 |
| 接受或撤销 AccessInvitation | 必须 | 必须匹配 AccessInvitation | accept 要求 Session 的 `verified_for_invitation_id` 与 path ID、`verified_contact_point_id` 与 invitation contact ID 都精确相等；行锁、状态/期限、命令收据和唯一约束 |
| 接受政策或授予 consent | 必须 | 必须匹配 User | append-only evidence 与 User 版本同事务 |
| 撤回 consent | 必须 | 必须匹配 ConsentGrant | append-only Withdrawal 与 ConsentGrant 终态同事务 |
| logout / revoke Session | 必须 | 不要求 | 单调安全命令；重复调用返回同一安全终态，不能因 stale ETag 阻止撤销 |
| 内部 SYSTEM bootstrap/expire | 外部 header 不适用 | 按目标聚合 | 内部 command_id、source_event_id/correlation_id 唯一，仍写 receipt/audit/outbox |

例外只改变协议携带方式，不豁免重复、并发、审计、原子性和隐私测试。新增例外必须修改本 ADR，不能由单个 handler 自行决定。

### Callback 使用 claim、事务外 exchange、最终提交三阶段

callback不能把provider网络调用放进数据库事务。入口先以retained key解析exact state digest并比较browser cookie、deadline、issuer/audience/redirect和冻结purpose/binding；随后用短事务CAS `PENDING/v1 → EXCHANGING/v2`，写唯一exchange owner、attempt=1与claimed_at并先提交。只有确认claim commit成功的owner可以在事务外调用一次code exchange；竞争callback看到EXCHANGING或终态不得再次调用provider。

claim COMMIT unknown时不调用provider并返回`COMMAND_OUTCOME_UNKNOWN`。claim提交后若进程在持久化provider结果前丢失，系统只能把超时EXCHANGING收口为RESULT_UNKNOWN，不能假定code未使用。provider调用前的无副作用preflight失败可保持PENDING；code发出后任何网络/取消/响应不确定都进入RESULT_UNKNOWN且不自动重试。明确拒绝进入FAILED。成功结果在第二个短事务锁回AuthTransaction并复核owner/attempt/deadline与全部onboarding事实，原子写ExternalIdentity/User/contact/Session以及`SUCCEEDED/v3`。最终COMMIT unknown同样返回`COMMAND_OUTCOME_UNKNOWN`，不得重做exchange或重建raw Session/CSRF。

callback Session的`auth_time/acr/amr`来自本次adapter验证结果，不继承请求context或predecessor；登录/step-up在同family轮换时以server now建立新的30分钟idle、12小时absolute exclusive deadline。匿名成功创建family generation1；已有Session发起的LOGIN/STEP_UP必须在最终事务重新证明initiating Session/family仍ACTIVE/current且provider subject解析到冻结expected User，否则统一拒绝，不能fallback为匿名登录。

### AccessInvitation capability token

邀请链接使用版本化 HMAC capability token。token 只包含协议版本、key ID、随机 invitation ID/nonce 和过期时间，不包含组织名称、角色、联系人或政策内容。角色、组织、状态和期限始终从数据库读取。

数据库保存 nonce 和 key ID，不保存可直接使用的 bearer token；服务端可为原始 actor + 同一 Idempotency-Key 确定性重建同一响应，从而同时满足秘密最小化和幂等重放。验证密钥至少保留到该 key 下全部邀请进入终态并超过必要的命令收据保留窗。

浏览器加入链接把 token 放在 URL fragment，前端只把它提交给安全 inspect 和 `BeginOidcAuthorization`。AuthTransaction 验证并绑定 exact invitation ID/version 与 expected contact row；callback 只有在 verified claim 精确匹配该不可变 contact tuple 时，才建立同时带 `verified_for_invitation_id` 与 `verified_contact_point_id` 的 Session。浏览器随后立即清除 token；`AcceptAccessInvitation` 不再次接收 token。服务端路径、query、访问日志、Referrer、审计和 outbox 不得包含 token。完整绑定和 accept 守卫以 ADR-0004 为准。

### 初始安全时限版本

开发和测试使用不可变 `iam-security-v1`：

| 控制 | 值 |
| --- | --- |
| AuthTransaction 绝对期限 | 10 分钟 |
| AccessInvitation 默认期限 | 7 天 |
| AccessInvitation 最大期限 | 30 天 |
| Session idle 期限 | 30 分钟 |
| Session 绝对期限 | 12 小时 |
| ORG_ADMIN 角色管理所需 MFA auth_time 新鲜度 | 10 分钟 |

所有期限使用可注入的服务端 UTC clock；客户端时间不参与守卫。调整这些值需要新的安全策略版本、回归测试和真实启用审查，不能覆盖历史命令证据。

## 被否决的方案

### 浏览器保存 OIDC access/refresh token

这扩大 XSS 和供应商 token 泄漏面，也使平台难以即时撤销组织权限，因此不采用。

### 无状态 JWT 保存角色和组织

它会让角色、Membership 暂停和政策撤回在 token 到期前继续有效，并造成 active tenant 混淆，因此首版不采用。未来机器 API 若需要短期 access token，仍必须以独立 ADR 定义撤销和 audience 边界。

### 本地密码与自建恢复

它引入凭据存储、撞库、恢复和 MFA enrollment 的额外高风险面，并非首个纵切面的必要依赖，因此不采用。

### Invitation magic link 同时作为登录凭据

链接可被转发、预取或泄漏，不能单独证明预期接收者身份。它只提供加入授权，仍需 OIDC verified recipient binding。

### 强迫 OIDC callback 携带平台 Idempotency-Key

身份供应商重定向不能保证自定义 header；伪造 header 或把 key 放入 URL 反而增加泄漏，因此用协议原生的一次性事务控制替代。

## 后果

- 首版需要持久化 AuthTransaction 和 Session，并在每次授权读取当前 User/Membership/Policy 状态。
- 服务端会话使即时撤销、session family 重放检测和安全审计明确，但需要清理过期记录与可用性监控。
- OIDC provider 可以替换，领域层只依赖已验证 AuthenticatedSubject；真实 adapter 仍默认关闭。
- 密码恢复由 IdP 承担并非免测：fake/adapter 契约仍需覆盖恢复后的 auth_time、MFA claim 和绑定变化。
- 通用幂等规则保持默认，协议例外被限制在可枚举入口并具有等价防重放控制。

## 验证义务

- `REQ-AUTH-001` / `DES-AUTH-001`：state、nonce、PKCE、issuer、audience、redirect、code 重放和时间边界均有 fake/adapter 契约测试。
- `REQ-AUTH-002` / `DES-AUTH-002`：新主体无有效邀请不创建 User；verified recipient 不匹配统一失败；邮箱不能自动链接账户。
- `REQ-SESSION-001` / `DES-SESSION-001`：cookie、CSRF、Origin/CORS、session fixation、轮换、idle/absolute expiry 和日志脱敏均有安全测试。
- `REQ-SESSION-002` / `DES-SESSION-002`：logout、User 暂停、Membership 暂停和旧 handle 重放具有各自明确影响范围。
- `REQ-IAM-004` / `DES-IAM-004`：每种协议例外都具有重复、并发、故障和稳定响应测试，且不存在未登记的旁路。

对应完整命令、API、表和 TEST ID 见 [身份、租户、政策同意与会话设计](/architecture/identity-tenancy-consent.md)。
