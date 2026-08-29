# IAM HTTP transport 与 ASGI 边界

> 状态：框架无关 protocol kernel、原始 ASGI 边界两轮 hardening 与 25-operation 生产 presenter registry 均已通过语义 GREEN；持久 Session authenticator、真实 server/composition build contract、反向代理/TLS 与浏览器 E2E 尚未完成
> 适用范围：`platform/contracts/api/iam-v1.openapi.yaml` 的 25 个公开 operation
> 不包含：应用命令本身、OIDC provider、PostgreSQL adapter、Outbox worker、反向代理/TLS 配置和浏览器 UI

本文把 [IAM 业务与协议设计](/architecture/identity-tenancy-consent.md)、[ADR-0003](/decisions/0003-oidc-bff-session-and-protocol-exceptions.md)、[ADR-0004](/decisions/0004-iam-onboarding-persistence-and-postgres.md) 和 `iam-v1.openapi.yaml` 补成可实现的 transport 协议。OpenAPI 已关闭业务 DTO，却没有裁决 ASGI body 如何读取、重复 carrier 如何处理、安全检查发生在 handler 前还是后、异常如何落到稳定 envelope，以及客户端断线或 response start 后失败时能否重试；这些结论不得留给框架默认值。

首切片直接实现 ASGI 3 callable 与框架无关的 immutable kernel contract，不引入 Web framework 或 JSON Schema runtime。标准库足以表达边界；若以后选择 FastAPI、Starlette 或其他框架，必须用 ADR 说明依赖、默认解析/异常/日志行为及其与本文的逐项等价性，不能以框架默认值改写本协议。

## 1. 要求、完成定义与非目标

| ID | 要求 |
| --- | --- |
| `REQ-HTTP-IAM-001` | OpenAPI 的每个 method/path 恰映射一个固定 operation；未知 path 是 404，已知 path 的不支持 method 是 404，缺 presentation binding 是 503，三者不得混淆。 |
| `REQ-HTTP-IAM-002` | path/query/header/cookie/JSON 都先按关闭 grammar、数量、类型和字节上限规范化，再调用认证或业务 handler；未知、重复、歧义、非 UTF-8、超限和断线全部 fail closed。 |
| `REQ-HTTP-IAM-003` | cookie Session、Origin/CORS、CSRF、OIDC browser cookie 及匿名/可选/必需认证矩阵在单一 protocol kernel 执行，业务 handler 不能自创绕过。 |
| `REQ-HTTP-IAM-004` | application 的稳定错误只映射到 OpenAPI 的关闭 error envelope/status/header；COMMIT outcome unknown 不被 transport 自动重试或伪装为确定失败。 |
| `REQ-HTTP-IAM-005` | 请求、响应、错误、结构化日志、trace 与指标标签不泄漏 Cookie、CSRF、capability、OIDC code/state、authorization URL、原始 recipient 或 provider 正文。 |
| `REQ-HTTP-IAM-006` | Session rotation 只在首次成功响应发出 successor cookie；completed receipt replay 只返回安全 JSON/ETag，绝不重建或重放 Set-Cookie/CSRF。 |

`TEST-HTTP-IAM-001` 是本切片的可执行证据。完成 GREEN 至少要求：25/25 operation 通过真实 kernel 可达；关闭输入与安全矩阵在 handler 前拒绝；稳定状态/错误/headers 精确；ASGI chunk、disconnect、deadline 与 response-start fault 有测试；secret sentinel 不进入任何观测面。仅有 import、route 常量或 default-deny 503 不算实现完成。

以下不是本切片的目标：实现尚不存在的 IAM application use case、证明真实数据库并发、替代反向代理的 TLS/header hardening、实现浏览器页面、把 OpenAPI schema 动态解释成运行时授权策略。测试用 dispatcher 可以代表一个已经存在的 application handler，但生产 wiring 必须逐 operation 显式注册。

## 2. 两层边界与依赖方向

```mermaid
flowchart LR
    C["Browser / API client"] --> P["TLS reverse proxy"]
    P --> A["ASGI byte boundary"]
    A --> R["bounded body reader"]
    R --> K["IAM HTTP protocol kernel"]
    K --> S["Origin / Session / CSRF ports"]
    K --> D["operation presenters"]
    D --> H["application handlers"]
    H --> D
    D --> K
    K --> A
    A --> C
```

依赖只向内：

1. **ASGI byte boundary** 只理解 ASGI HTTP scope、`http.request`、`http.disconnect`、`http.response.start/body`；它不解析领域 DTO，也不捕获任意 `Exception` 冒充业务错误。
2. **protocol kernel** 路由、解析、规范化、执行安全矩阵、调用一个显式 operation presenter，并把关闭结果/稳定错误序列化。它不直接读数据库或环境变量。
3. **operation presenter** 把已经验证的 path/header/body/actor 显式构造为公开 application command/context，调用对应 `handle`，再从 safe result 构造关闭 DTO。它不得传递原始 Request，也不得从 `Accept-Language`、cookie 或 body 重算 policy selector、tenant、role、recipient、User ID。
4. **application handler** 继续拥有事务、receipt、锁、COMMIT outcome、授权和领域不变量。HTTP 层不重试写命令，也不检查数据库来“确认”一次不确定提交。

首版生产包边界固定为 `desire_platform.http`。`HttpRequest`、`HttpResponse`、header、route、operation/result contract 均为 frozen value；原始 headers/query/body 和任何 cookie/token 字段必须 `repr=False`。值对象不可持有可变 dict/list。请求对象只是受控进程内载体，不是可记录 DTO。

## 3. Immutable request/response contract

### 3.1 ASGI 归一化前请求

`HttpRequest` 关闭字段为：

| 字段 | 规则 |
| --- | --- |
| `method` | 大写 ASCII enum：`GET | POST | DELETE`；其他方法不会被转换成业务 operation。 |
| `scheme` | `https`；显式 synthetic test profile 可为 `http`，生产启动配置不得允许。不得信任任意 `X-Forwarded-*`；只有受信 proxy adapter 可以先生成已验证 scheme/host。 |
| `path` | ASGI `raw_path` 严格 percent-decode 一次后的 NFC Unicode path；首版 IAM ID 和固定 segment 仅允许 OpenAPI ASCII grammar。 |
| `raw_query_string` | 原始 bytes，敏感且不进入 repr/log；kernel 负责 form-style 解析但 `+` 不作为 path 规则。 |
| `headers` | 保留顺序的 immutable byte-pair；名称由 adapter 校验为小写 ASCII token，值拒绝 CR/LF/NUL。 |
| `body` | 完整、受上限保护的 bytes，`repr=False`；GET/DELETE 必须为空。 |
| `client_disconnected` | reader 在完成前收到 `http.disconnect` 时为 true；这种请求不会进入 kernel/handler。 |

不能从 ASGI `scope["client"]`、User-Agent 或 forwarded header 推导身份或幂等事实。可信 proxy 生成的 coarse network bucket 以后可经独立值对象供 rate limiter 使用，但完整 IP/User-Agent 不进入 application command、receipt 或普通 telemetry。

### 3.2 已验证 invocation

kernel 只能向 presenter 传 `IamHttpInvocation`：固定 operation、canonical path、关闭 path/query 值、关闭 JSON 值、已认证 actor/session 事实、解析后的 expected aggregate version、原始 Idempotency-Key 的敏感载体、server trace ID 与受控 deadline。以下事实不再传入：Cookie header、raw Session handle、raw CSRF、Origin、OIDC browser cookie、provider error description；相应 port 已在边界验证并只返回必要的稳定事实。

JSON object 在内核中表示为有序 immutable key/value tuple，array 为 immutable tuple；只允许 `null | bool | int | NFC string | array | object`。首版拒绝 float、NaN/Infinity、重复 key 和超出 signed 64-bit 的整数。presenter 为某一 command 构造正式 dataclass 前仍逐字段读取，不执行 `**request_dict`。

### 3.3 应用结果与 HTTP 响应

presenter 返回关闭的 `IamHttpOperationResult`，包含 status、safe JSON body 或空 body、可选 entity tag、可选首次 session/temporary-cookie mutation、可选登记 redirect、replayed 标志和受控 retry-after。cookie mutation 的 raw value `repr=False`，且只允许下表列出的 operation；其他 operation 返回它时视为服务端配置错误并 503，而不是发出 cookie。

`HttpResponse` 只包含 status、immutable headers 和 bytes body。serializer 固定紧凑 UTF-8 JSON（无 BOM，拒绝非有限数，响应 key 由 presenter 固定），补 `Content-Type: application/json`。它不自动序列化 dataclass、ORM row、异常对象或任意 mapping。

## 4. 固定 route 与安全矩阵

route registry 是编译期常量，不从 OpenAPI 在生产启动时动态生成；contract test 将它与 OpenAPI operationId 做 exact diff。path template 只允许固定 segment 与一个明确的 `OpaqueId` 参数；拒绝空 segment、`//`、`.`/`..`、反斜线、编码斜线、双重编码、NUL 和尾部斜线别名。已知 template 中 path ID 不满足 `^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$` 时返回 404，避免暴露内部 parser 分类。

| Method/path | operationId | 认证 | Origin / CSRF | body 上限 |
| --- | --- | --- | --- | --- |
| `POST /v1/auth/oidc/authorizations` | `beginOidcAuthorization` | optional Session | exact Origin；若 attached ACTIVE Session 参与 LOGIN/STEP_UP，必须同时验证该 Session 的 CSRF；匿名无 CSRF | 8 KiB |
| `GET /v1/auth/oidc/callback` | `completeOidcAuthorization` | required `__Host-ds_oidc` browser binding；不用 Session auth | OIDC state/browser/nonce/PKCE 例外；不要求 Origin/普通 CSRF | 无 body；query 8 KiB |
| `GET /v1/auth/session` | `getSessionBootstrap` | required Session | 无 CSRF | 无 body |
| `POST /v1/access-invitations/inspect` | `inspectAccessInvitation` | anonymous | exact Origin；无 Session CSRF；限速 fail closed | 8 KiB |
| `POST /v1/access-invitations/{invitation_id}/accept` | `acceptAccessInvitation` | required Session | exact Origin + CSRF | 64 KiB |
| `POST /v1/access-invitations/{invitation_id}/revoke` | `revokeAccessInvitation` | required Session | exact Origin + CSRF | 4 KiB |
| `GET /v1/policy-bundles/{policy_bundle_id}` | `getPolicyBundle` | anonymous | 无 | 无 body |
| `GET /v1/me` | `getMe` | required Session | 无 CSRF | 无 body |
| `POST /v1/me/policy-acceptances` | `acceptCurrentPolicies` | required Session | exact Origin + CSRF | 64 KiB |
| `GET /v1/me/consents` | `listMyConsentGrants` | required Session | 无 CSRF | 无 body |
| `POST /v1/me/consents` | `grantConsent` | required Session | exact Origin + CSRF | 8 KiB |
| `POST /v1/me/consents/{consent_grant_id}/withdraw` | `withdrawConsent` | required Session | exact Origin + CSRF | 4 KiB |
| `GET /v1/me/sessions` | `listMySessions` | required Session | 无 CSRF | 无 body |
| `DELETE /v1/me/sessions/{session_id}` | `revokeMySession` | required Session | exact Origin + CSRF | 无 body |
| `GET /v1/organizations/{organization_id}` | `getOrganizationSummary` | required Session | 无 CSRF | 无 body |
| `POST /v1/organizations/{organization_id}/public-name` | `updateOrganizationPublicName` | required Session | exact Origin + CSRF | 4 KiB |
| `GET /v1/organizations/{organization_id}/access-invitations` | `listOrganizationAccessInvitations` | required Session | 无 CSRF | 无 body |
| `POST /v1/organizations/{organization_id}/access-invitations` | `issueOrganizationAccessInvitation` | required Session | exact Origin + CSRF | 8 KiB |
| `GET /v1/organizations/{organization_id}/memberships` | `listOrganizationMemberships` | required Session | 无 CSRF | 无 body |
| `POST /v1/memberships/{membership_id}/suspend` | `suspendMembership` | required Session | exact Origin + CSRF | 4 KiB |
| `POST /v1/memberships/{membership_id}/resume` | `resumeMembership` | required Session | exact Origin + CSRF | 4 KiB |
| `POST /v1/memberships/{membership_id}/revoke` | `revokeMembership` | required Session | exact Origin + CSRF | 4 KiB |
| `POST /v1/platform/users/{user_id}/suspend` | `suspendUser` | required Session | exact Origin + CSRF | 4 KiB |
| `POST /v1/platform/users/{user_id}/resume` | `resumeUser` | required Session | exact Origin + CSRF | 4 KiB |
| `POST /v1/platform/users/{user_id}/revoke-all-sessions` | `revokeAllUserSessions` | required Session | exact Origin + CSRF | 4 KiB |

OpenAPI 未列 `OPTIONS` 为业务 operation。ASGI adapter 可以为已登记 route 生成受控 CORS preflight；它不调用 presenter，不扩大 method/path，不允许 credentials + `*`，只回显逐字命中的 configured HTTPS origin、允许的固定 method/header，设置 `Vary: Origin`，并拒绝 `null`、多 Origin、带 path/query/userinfo 的 Origin。非生产 loopback HTTP 只能通过显式 synthetic profile 配置，不能由请求启用。

## 5. 读取、解析与关闭输入

### 5.1 读取上限与生命周期

- raw path 最多 2 KiB；query 最多 8 KiB；header 名/值各最多 8 KiB、总计最多 32 KiB、最多 100 对；Cookie 总计另受 header 总上限保护。
- 先匹配 method/path 得到 route-specific body limit，再读取 body。`Content-Length` 缺失时仍按 chunk 累加；非十进制、负数、重复不一致或声明超过上限均在读取前拒绝。声明较小但实际更多仍按实际 bytes 拒绝。
- reader 每次只接受 `http.request` 或 `http.disconnect`。累计到 `limit + 1` 即停止、清除 buffer、不调用任何 security/application port，并返回 400 `INVALID_REQUEST` + `field_issues=[{path:"body",code:"TOO_LARGE",...}]`。OpenAPI 未发布 413，因此首版不自创 413。
- headers 完成、首 body byte、相邻 chunk 和总读取均使用注入的 monotonic clock/deadline；超时在 handler 前返回 503 `SERVICE_UNAVAILABLE`，不回显读取状态。disconnect 在 handler 前不发送响应且零 handler 调用。
- GET/DELETE 带非空 body、POST 缺 required body，或空 body 配 `application/json` 但 schema 要求 object，均为 400。

### 5.2 Content-Type 与 JSON

有 JSON requestBody 的 operation 必须恰有一个 `Content-Type`，media type 大小写不敏感地等于 `application/json`；只允许零参数或单一 `charset=utf-8` 参数。缺失、重复、其他 media type/charset、无效 quoting 均为 400。无 requestBody 的 operation 不得携带 Content-Type 或非空 body。

body 必须是合法 UTF-8、顶层 object、无 BOM、无尾随 token、无重复 key。schema 递归执行 `required`、关闭 unknown fields、type/const/enum/pattern/format/min/max、array items/数量/unique 和 oneOf exactly-one。字段问题的 `path/code/message` 使用固定模板，最多 100 项，按请求字段规范顺序输出；message 不含实际值。结构错误统一 400 `INVALID_REQUEST`，已经通过结构但违反关闭业务 input contract 才可由 application 返回 OpenAPI 已登记的 422。

`updateOrganizationPublicName` 的 body 必须恰为 `{public_name, reason_code}`，`reason_code` 恰为 `PUBLIC_NAME_CORRECTION`。除 OpenAPI 的长度/形状外，transport 使用同一 Unicode 边界确认 `public_name` 已 NFC、首尾 trim 后逐字不变、含 1..160 个 code point，且不含 category `Cc`/`Cf`；不得只依赖只覆盖部分控制字符的 regex，也不得自动 normalize 或 trim 后代用户提交。

### 5.3 Header、Cookie、query 与 If-Match

- header name 先验证 ASCII token 再小写。`cookie`、`origin`、`content-type`、`content-length`、`idempotency-key`、`if-match`、`x-csrf-token`、`traceparent` 重复即 400；不能用逗号合并安全 carrier。
- Cookie 按单一 Cookie header 的 `;` 分隔解析；空名、CTL、quoted ambiguity、重复 `__Host-ds_session` 或 `__Host-ds_oidc` 均拒绝。未知 cookie 被忽略但永不记录；目标 cookie 的 raw value 只进对应 verifier port。
- query 使用 UTF-8 percent-decode 一次；无效 escape、重复已知 scalar、unknown key、空 required 值或 `+`/编码歧义拒绝。callback 的 `state/code/error/error_description` 全部敏感；`code` 与 `error` 必须 exactly-one，详细 provider error 不进 response/log。
- `Idempotency-Key` 逐字按 OpenAPI 16..128/base64url grammar 验证后以 `repr=False` 传 application；transport 不 hash、不缓存、不记录它。
- `If-Match` 只接受一个强 tag `"v<positive-decimal>"`，拒绝 `W/`、`*`、列表、前导零、溢出；presenter 只传解析后的 expected version，同时 receipt canonical payload 仍由 application 绑定 HTTP method/canonical path/target/If-Match。
- Organization 更名的 412 只在 application 提供 typed current Organization ETag 时附 `ETag`；格式错误或其他未绑定实体的错误不由 transport 猜测 tag。
- cursor 是 opaque sensitive-ish carrier，只传受控 pagination port，不进入日志/metric；`limit` 只接受十进制 1..100，重复或前导符号拒绝。

## 6. 认证、Origin、CORS 与 CSRF 顺序

kernel 固定以下顺序，避免 parser、认证或业务错误成为枚举 oracle：

1. 验证 scope、method、canonical path、headers/query/body byte limits；
2. route 匹配；未知/隐藏 path 统一 404 `RESOURCE_NOT_FOUND`；
3. content-type 和关闭 JSON 结构；
4. 对 unsafe route 验证 exact Origin；不匹配以 400 `INVALID_REQUEST` 关闭，且不添加允许跨域读取的 CORS header；
5. 按 route 解析目标 cookie，并通过 Session authenticator 返回最小 `AuthenticatedHttpActor`。缺失/无效/撤销为 401 `AUTHENTICATION_REQUIRED`，已验证但到 exclusive deadline 为 401 `SESSION_EXPIRED`；配置/历史 key 不可用为 503 `SERVICE_UNAVAILABLE`；
6. 需要时用 raw cookie + raw CSRF 调用 verifier，并要求其 session ID/generation 与认证结果精确一致。缺失/格式错/不匹配以 400 `INVALID_REQUEST` 关闭；旧 handle replay 的 family 撤销属于 Session application/security port，不由 HTTP 猜测；
7. rate limiter、安全 handler 与 operation presenter；
8. 序列化关闭结果。

可选 Session 的 OIDC begin 不把无效/过期 cookie 当作任意 actor；遵循 ADR-0004 把它当匿名后，invitation token 仍独立验证。若 cookie 被成功解析为 ACTIVE Session，CSRF 也必须成功，防止跨站发起该 User 的 LOGIN/STEP_UP。callback 只验证 `__Host-ds_oidc` + transaction protocol，不读取普通 CSRF；inspect 永远匿名且零写，即使浏览器附带 Session cookie也不把它传给 handler。

认证对象是关闭且不可变的 `AuthenticatedHttpActor`，只含 `actor_user_id/session_id/original_actor_id/auth_time/acr_code/amr_codes/correlation_id/causation_id/trace_id`。`auth_time` 必须是 UTC aware 的持久 Session 事实，`amr_codes` 必须是去重的非空 tuple；这些值由 Session authenticator 从 ACTIVE User/Family/Session 图读取，不是 header/body 声明。它不携带 organization、role、target actor、policy selector、recipient 或任意 claims mapping；这些权威事实都由 application 沿 path resource 和数据库关系重新解析。

## 7. Presenter 到 application handler

每个 operationId 必须在 composition root 显式绑定一个 presenter。通用反射、按函数名 import、`**body`、未登记 fallback handler 均禁止。已登记 route 但 presenter/依赖缺失返回 503 `SERVICE_UNAVAILABLE`；不能返回 404 假装 route 不存在，也不能让 default fake 处理真实请求。`IamHttpApplicationDispatcher` 只接受一个关闭 `IamHttpPresenterBindings`，按下表的固定分支构造 command/query；结果仅从 handler 的 safe response 构造 `IamHttpOperationResult`。

| operationId | 固定 application 输入 | 固定 presentation 结果 |
| --- | --- | --- |
| `beginOidcAuthorization` | `BeginOidcAuthorizationCommand(return_to, access_invitation_token)` + `OidcBrowserContext`；可选 current Session 只来自 authenticator | 201 `BeginOidcAuthorizationResponse`，设置一个 OIDC browser cookie |
| `completeOidcAuthorization` | callback query 构造 `CompleteOidcAuthenticationCommand`，exact raw OIDC cookie 进 `OidcBrowserContext` | 303 到登记 `return_to`，设置 Session cookie 并清 OIDC cookie |
| `getSessionBootstrap` | `GetSessionBootstrapQuery(ReadActor, raw_session_handle)` | handler `ReadModelResponse`，no-store |
| `inspectAccessInvitation` | body token 构造 `InspectAccessInvitationQuery` | safe preview + handler ETag |
| `acceptAccessInvitation` | path ID + parsed If-Match + Idempotency-Key + exact policy/consent arrays 构造 `AcceptAccessInvitationCommand` 和 `ActorContext` | handler `safe_response`，ETag 只取 `invitation.entity_tag`；首次设 successor Session cookie，replay 不设 |
| `revokeAccessInvitation` | `RevokeAccessInvitationCommand` + `LifecycleActorContext` | `AccessInvitationAdminDto` + DTO `entity_tag` |
| `getPolicyBundle` | path ID 构造 `GetPolicyBundleQuery` | public immutable handler body/ETag/cache policy |
| `getMe` | `GetMeQuery(ReadActor)` | handler body/ETag |
| `acceptCurrentPolicies` | body 必须含 exact `policy_requirement`、bundle 和 acceptances；构造 `AcceptCurrentPoliciesCommand` | handler body + `response_entity_tag` |
| `listMyConsentGrants` | `ListMyConsentGrantsQuery(ReadActor, PageRequest)` | handler page；cursor 不写日志 |
| `grantConsent` | body 必须含 exact `policy_requirement`、bundle 和 offer/document/hash/affirmed；构造 `GrantConsentCommand` | 201 handler body + `response_entity_tag` |
| `withdrawConsent` | path ID + reason + If-Match 构造 `WithdrawConsentGrantCommand` | `ConsentGrantDto` + DTO `entity_tag` |
| `listMySessions` | `ListMySessionsQuery(ReadActor, PageRequest)` | handler page |
| `revokeMySession` | path ID 构造 `RevokeSessionCommand` | 204；仅当 handler 证明撤销 current Session 时清 Session cookie |
| `getOrganizationSummary` | path org ID 构造 `GetOrganizationSummaryQuery` | handler body/ETag |
| `updateOrganizationPublicName` | path org ID + parsed Organization If-Match + Idempotency-Key + exact `{public_name, PUBLIC_NAME_CORRECTION}` 构造 `UpdateOrganizationPublicNameCommand` 和已认证 actor context | 200 `OrganizationSummaryDto` + 新 Organization ETag；无 cookie mutation |
| `listOrganizationAccessInvitations` | path org ID + `PageRequest` | handler page |
| `issueOrganizationAccessInvitation` | OpenAPI recipient/role/expires_at + path/header 事实构造 `IssueAccessInvitationCommand` 和 USER `InvitationIssuerContext` | 201 safe invitation + one-time token/fragment + invitation ETag；replay 仍仅来自 receipt |
| `listOrganizationMemberships` | path org ID + `PageRequest` | handler page |
| `suspendMembership` | path ID + reason + If-Match 构造 `SuspendMembershipCommand` | safe `MembershipAdminDto` + DTO ETag |
| `resumeMembership` | 同上，构造 `ResumeMembershipCommand` | safe `MembershipAdminDto` + DTO ETag |
| `revokeMembership` | 同上，构造 `RevokeMembershipCommand` | safe `MembershipAdminDto` + DTO ETag |
| `suspendUser` | path User ID + reason + If-Match + Idempotency-Key 构造 `SuspendUserCommand` | safe `PlatformUserAdminDto` + DTO ETag |
| `resumeUser` | 同上，构造 `ResumeUserCommand` | safe `PlatformUserAdminDto` + DTO ETag |
| `revokeAllUserSessions` | 同上，构造 `RevokeAllSessionsCommand` | safe `PlatformUserAdminDto` + DTO ETag |

Presenter 对 normalized invocation 仍执行关闭内部不变量校验：operation/path/path-parameter 必须一致，required actor/header/raw carrier 必须存在，UTC timestamp 必须严格解析，handler 结果的 operation/status/body/ETag/cookie 组合必须与上表一致。这些内部不变量损坏统一映射 503，不伪装成用户 400/404。Presenter 不重算 selector、consent authority、organization role 或 Session auth strength，不可直接序列化 domain aggregate/repository row。HTTP 永远不能构造 SYSTEM Issue credential。

## 8. 稳定错误、缓存与响应 headers

所有失败 body 恰为 OpenAPI `ErrorResponse`：`code/message/trace_id/field_issues`，仅 `POLICY_BUNDLE_CHANGED` 可按 schema携带 `current_policy_bundle_id`。未知内部异常不回显类型、`repr`、SQL/provider 文本或 carrier，记录安全 fault class 后返回 503 `SERVICE_UNAVAILABLE`。message 是 code 对应的固定英文模板，不插入请求值；trace ID 由服务端生成，客户端 header 不可指定。

| HTTP | 稳定 code |
| --- | --- |
| 400 | `INVALID_REQUEST`（含 JSON/header/query/path carrier 格式、Origin/CSRF、大小） |
| 401 | `AUTHENTICATION_REQUIRED`、`SESSION_EXPIRED`、`AUTH_TRANSACTION_INVALID`、`AUTHENTICATION_REJECTED` |
| 403 | `POLICY_ACCEPTANCE_REQUIRED`、`CONSENT_REQUIRED_FOR_PURPOSE`、`MFA_STEP_UP_REQUIRED`、`SAFETY_HOLD_BLOCKED` |
| 404 | `RESOURCE_NOT_FOUND`、`ACCESS_INVITATION_UNAVAILABLE` |
| 409 | `IDEMPOTENCY_KEY_REUSED`、`POLICY_BUNDLE_CHANGED`、`MEMBERSHIP_ALREADY_EXISTS`、`INVALID_STATE_TRANSITION`、`LAST_ACTIVE_ORG_ADMIN` |
| 412 | `PRECONDITION_FAILED`；若 application 提供当前安全 ETag则发送，否则不猜测 |
| 429 | `RATE_LIMITED`；只允许受控 1..86400 秒 `Retry-After` |
| 503 | `IDENTITY_PROVIDER_UNAVAILABLE`、`POLICY_CONFIGURATION_UNAVAILABLE`、`SAFETY_DECISION_UNAVAILABLE`、`COMMAND_OUTCOME_UNKNOWN`、`SERVICE_UNAVAILABLE`；仅确定 safe delay 时发 `Retry-After` |

`updateOrganizationPublicName` 的新 key 提交与当前名称相同时使用 409 `INVALID_STATE_TRANSITION`；exact completed receipt replay 在该检查之前返回原 200 body/ETag。same-org ACTIVE ORG_ADMIN 和 recent MFA 由 application/PostgreSQL 重验，transport 不从 path、body 或 UI capability 推导角色。

application 返回未登记 code、code/status 不一致、错误 envelope 含 unknown field 或非安全 message 时，transport 改为 503 `SERVICE_UNAVAILABLE` 并记录安全 invariant metric。它不把 `IamError.code` 当作任意 HTTP status。

除公开 immutable policy bundle 的成功 GET 外，IAM 响应一律 `Cache-Control: no-store`；所有错误也 no-store。公开 policy 成功响应按 OpenAPI 使用 `public, max-age=31536000, immutable`，且只因 path ID 指向不可变 ACTIVE bundle，不使用 Session Vary。强 ETag 由 application safe result/aggregate_version 构造，transport 不从 JSON bytes或数据库时间猜测。响应固定 `X-Content-Type-Options: nosniff`；认证/CORS响应按 exact origin 设置 `Vary: Origin`。

## 9. Cookie mutation 与 Accept receipt replay

cookie serializer 只有三个 allowlisted动作：

| operation | 动作 |
| --- | --- |
| `beginOidcAuthorization` 首次成功 | 设置 `__Host-ds_oidc=<raw>; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`，省略 Domain |
| `completeOidcAuthorization` 首次成功 | 设置新的 `__Host-ds_session=<raw>; Secure; HttpOnly; SameSite=Lax; Path=/`，并以独立 Set-Cookie 清除 `__Host-ds_oidc` |
| `acceptAccessInvitation` 首次成功 | 设置 successor `__Host-ds_session`，不在 body/header暴露 CSRF；客户端随后从 `/auth/session` 取得新 token |
| `revokeMySession` 撤销 current Session | 清除 `__Host-ds_session`；撤销其他 Session 或 receipt replay 的结果仍依 handler 的持久 `clear_current_session_cookie` 事实，不由 HTTP 比较 path 猜测 |

`AcceptAccessInvitationResult.replayed=False` 必须有一次 `SessionRotation`，transport 才能发送 successor cookie；`replayed=True` 必须 `session_rotation is None`，返回 receipt 的 safe body/ETag且 **没有** `Set-Cookie`。违反任一组合视为服务端不变量损坏并返回 503；transport 不从 receipt、session row、body 或旧 cookie重建 raw successor。响应在网络中丢失后，ADR-0003/0004 的重新 LOGIN + completed receipt replay 路径保持成立。

Set-Cookie header 自身标记 sensitive，不能进入 access log/trace。应用结果若在非 allowlisted operation 请求 cookie mutation，或 cookie名/flags不是固定策略，transport拒绝整个结果。

## 10. COMMIT unknown、断线、超时与 ASGI fault

- transport 对 GET/POST/DELETE 都不做 application 自动重试。Idempotency-Key 允许客户端重试，不授权中间件在不知事务阶段时重放 handler。
- application 抛出 `COMMAND_OUTCOME_UNKNOWN` 时返回 503 同 code/no-store；不得换成 409/500，不得查询另一个副本猜成功，也不得再次调用 handler。
- disconnect/timeout 若发生在 presenter 调用前：清除 buffer/secret，零 handler 调用；可以不发送任何 ASGI response。
- presenter 已开始后，ASGI disconnect 不等于 transaction取消。adapter把 disconnect 通知受控 deadline context，允许同步 handler在 bounded grace内完成其 own commit/receipt协议，但不再发送响应；不得因为客户端消失而启动第二次命令。
- transport 自己的 outer deadline 若在写 handler进入后触发，不能假定未提交；只在连接仍可写且 application给出确定 fault 时发送相应 envelope，否则按 `COMMAND_OUTCOME_UNKNOWN` 收口并告警。读 handler可在明确无副作用时取消。
- 在 `http.response.start` 之前，序列化/cookie/header不变量失败可安全改写为 503 envelope；start 之后不能再发送第二个 status。后续 write fault 只终止 response并记安全 metric，客户端靠幂等协议恢复。
- ASGI `send` 的 before-ack/after-ack 不确定不改变应用事务事实。特别是成功 response start/body 发出后连接异常，transport绝不回滚或重复 command。
- graceful shutdown 先停止接收新请求；等待已进入 application 的命令到 configured grace，随后让 application/DB 层按其 commit-unknown规则收口。测试注入 monotonic clock，不使用真实 sleep；wall clock只传给领域/application。

### 10.1 第二轮 ASGI framing 与生命周期安全门禁

首轮18项测试没有覆盖 wire framing 被 ASGI server转换后的全部恶意 scope，也没有覆盖同步 dispatcher占住 event loop、dispatch后断线和 `send()` 失败。第二轮固定 `TEST-HTTP-IAM-SEC-002`，其失败不能再被首轮 `18/18` 的 GREEN 覆盖：

- adapter在第一次 `receive()` 前完成 header framing验证：header最多100对，单个名称/值最多8 KiB、总计最多32 KiB；名称必须是 ASGI规定的小写 ASCII token，值拒绝 CR/LF/NUL及其他 CTL。uppercase名称、重复 `Content-Length`（即使值相同）、非十进制/带符号/带空白、超过 signed 64-bit或十进制文本长到无法安全解析的 `Content-Length` 都稳定返回400、零 security/application port调用，不允许 Python整数转换异常逃出。
- ASGI scope中的 body已经由 server解 framing；因此 IAM adapter拒绝任何 inbound `Transfer-Encoding`。`Transfer-Encoding` 单独出现或与 `Content-Length` 同时出现都在读取 body前400，不能把 CL/TE选择留给 server、proxy与kernel分别解释；真实部署仍须另测反向代理和ASGI server的 wire-level request-smuggling门禁。
- `scope.path` 必须是无 surrogate的 NFC Unicode，`raw_path` 必须存在且为 bytes，并与单次、关闭的 path解码规则一致。编码失败、未配对 surrogate或 raw/decoded不一致稳定400，不得以 `UnicodeEncodeError`/`ValueError` 逃出 ASGI callable。
- body完成后，adapter必须在独立执行上下文调用同步 dispatcher，使 event loop仍可观察 monotonic deadline与 `http.disconnect`。写 operation到 deadline时只允许一次 dispatcher调用，不取消、重试或返回普通成功；连接仍可写时以503 `COMMAND_OUTCOME_UNKNOWN`收口，后台命令继续按业务UoW自己的 commit协议结束。读 operation可按明确无副作用的取消契约返回503 `SERVICE_UNAVAILABLE`。
- 快速同步 dispatch 先获得最多5ms、且不超过剩余总 deadline 的 completion observation window；未完成才开始 post-body disconnect probe。该 window 避免把测试/服务器在请求体结束后提供的兜底 disconnect 事件误判为已经发生的并发断线，同时仍保证阻塞 dispatcher 不占住 event loop。它不是 application 超时、重试窗口或事务取消信号。
- dispatch开始后收到 `http.disconnect` 时不发送响应、不重试，也不把断线解释为 rollback；adapter只通知受控 deadline/disconnect context并等待既定 grace。测试必须证明 receiver实际消费 disconnect、dispatcher恰调用一次且 response消息为零。
- `send()` 在 response start前或start后抛出的 `OSError`/connection fault都由adapter安全收口：不重试dispatcher、不发送第二个 status、不把 ASGI message、Set-Cookie、Location、response body或异常 `repr/args` 交给日志/telemetry。start前最多一次失败的send调用；start后最多一个 start和一次失败的body调用，随后正常终止 callable并记录关闭 fault class。

## 11. 隐私、日志、trace 与指标

入口先建立安全 request summary，之后才允许 telemetry。允许字段仅为：server trace ID、固定 operationId、method、route template、status、稳定 error code、粗粒度 duration/size bucket、authenticated yes/no、replayed yes/no。禁止标签/正文包括：

- raw path 中未规范化 segment、raw query、完整 URL；
- Cookie/Set-Cookie/Authorization、Session handle/digest、CSRF/token/key ID；
- `access_invitation_token`、join/authorization URL；
- OIDC state/code/error_description、nonce、PKCE、provider token/subject/locator；
- Idempotency-Key、cursor、recipient/email/phone、consent recipient reference；
- request/response body、exception repr/args、SQL parameters、arbitrary header values。

telemetry port 只接收关闭 `HttpTelemetryEvent`，不能接收 `HttpRequest`、`HttpResponse` 或 exception object。secret sentinel 在 malformed JSON、unknown field、错误 header/query/cookie、application error、timeout、disconnect和serializer fault各路径都必须证明不出现在 response、captured log、trace attributes或metric labels。trace baggage/tracestate默认拒绝；仅解析标准 `traceparent` 的格式并生成/连接服务端 trace，不把其原文传入业务错误。

## 12. TDD 切片与发布门禁

`TEST-HTTP-IAM-001` 分两层：

1. contract/application semantic test：OpenAPI 25 operation exact reachability；最小/完整 JSON；unknown/type/duplicate/UTF-8/content-type/size；header/cookie/query/path；认证/Origin/CSRF；401/403/404/409/412/429/503；ETag/no-store/CORS；Accept 首次 rotation 与 receipt replay；secret telemetry sentinel。
2. ASGI fault test：multi-chunk与 Content-Length；limit+1；disconnect before/after dispatch；timeout；response-start前后 fault；没有隐式 retry。

RED 有效条件：production import成功、默认行为稳定拒绝、fixture/async harness/OpenAPI oracle无错误，失败来自 handler 未调用或 status/body/header 与目标语义不同。不得通过放宽 OpenAPI、让 fake绕过kernel、把503当成功、删除privacy断言或只比较 operation常量转绿。

2026-08-08 的首轮 GREEN 保持同一 `18` 个 test method 与全部断言：exact 21-operation route/dispatch、关闭 parser、安全端口、稳定 response/cookie/cache/telemetry为 `12/12`；bounded ASGI chunk/limit+1/disconnect/timeout、COMMIT unknown不重试和秘密 fault 为 `6/6`。第二轮 `7/7` 再证明严格有界 Content-Length、CL/TE关闭、ASGI header/path grammar、同步 dispatch deadline、dispatch后断线及 start前后 send fault，累计 HTTP/ASGI `25/25 OK`。第二轮 RED 的 error oracle 曾错误加入未被 OpenAPI发布的 `error` wrapper；在实现 GREEN 前先恢复为权威 `ErrorResponse` 顶层 `code/message/trace_id/field_issues`，修正后仍保持 `7`项语义 RED（`9`个 assertion failure、`0` error），未以 fixture 变更替代生产实现。生产实现位于 `platform/src/desire_platform/http/`，只依赖标准库与注入 dispatcher/security ports；没有动态解释 OpenAPI，也没有补写缺失业务 handler。

`TEST-HTTP-IAM-PRESENTER-001` 严格遵循 design-first/TDD：先发布本节 21 分支表、富认证事实与 current-session cookie 裁决，再以可导入 default-deny registry 取得 `Ran 9 tests / 52 failures / 0 errors / 0 skips`。首轮 GREEN 使 21 个 normalized invocation 逐一构造正式 command/query/context，修正 kernel 对 OpenAPI `policy_requirement` 的遗漏、发布 current-session clear cookie，并证明全部 21 分支各只调用一个 handler。第二轮先对 actor UTC/AMR、anonymous/required actor、body/query/header 二次关闭和 read ETag 组合取得 `Ran 1 test / 8 failures / 0 errors / 0 skips`，再转为 GREEN。最终 presenter `11/11 OK`，与既有 transport/ASGI/contracts 合跑 `65/65 OK`；其中还用 keyed receipt oracle 发现并修正 `WithdrawConsentGrant` 曾绑定旧 `/v1/me/consent-grants/...` 而非已发布 `/v1/me/consents/...` 的路径漂移。生产实现是 `platform/src/desire_platform/http/iam_presenters.py`；它没有反射、`**body`、任意 handler lookup 或 fake fallback。

后续的 ACCESS_ADMIN 三分支与 IAM42 在不改写上述 2026-08-08 历史数据的前提下，已把当前 registry 扩展为 25 个关闭 operation。其中 `updateOrganizationPublicName` 的专项测试覆盖 4 KiB body、exact Origin/CSRF/If-Match/Idempotency-Key、Unicode `Cc`/`Cf`、typed 412 ETag、无 cookie mutation 和 safe `OrganizationSummaryDto`。

该 GREEN 仍不能宣称真实 IAM API 可发布：尚未有持久 Session authenticator/CSRF/origin/rate-limit 的 production adapter、真实 ASGI server/反向代理/TLS/CORS deployment、把 presenter 与所有持久 handler 组装的 production build contract 及浏览器 E2E。缺 dispatcher、安全 port 或其他 required binding 时 kernel 继续稳定 503/no-store；生产 composition root 必须在监听前把缺配置升级为启动失败，不能把 runtime unavailable 当长期降级模式。

### 12.1 持久 Session security adapter

`TEST-HTTP-IAM-SESSION-003` 负责把本页的 `SessionAuthenticator` 与
`CsrfVerifier` port落实为同一个 production component。该component只持有
`iam_session_authenticator` role-bound pool、用途隔离keyring、UTC/UUID source和关闭
settings；它不持有`iam_app`/owner/migration连接，不调用业务presenter，也没有Memory、
allow-all或active-key-only fallback。pool和keyring由composition root拥有，component的
`close()`不能偷偷关闭共享资源。

raw Session handle的生产grammar固定为43..128位base64url无padding，对应至少256 bit
CSPRNG输出。格式不合法或所有retained key均未命中统一为
`AUTHENTICATION_REQUIRED`；配置声明的任一retained key取不到可用material时为
`SERVICE_UNAVAILABLE`，不能把key丢失伪装成cookie无效。keyring关闭暴露：

```text
active_session_handle_key_id
retained_session_handle_key_ids  # 1..8，配置顺序、无重复，必须包含active
keyed_digest_hex(key_id, canonical_bytes)
```

每个retained key按配置顺序计算现有`iam-session-handle` domain-separated HMAC；raw值不
进入SQL、GUC、异常、`repr`、metric或trace。每个候选使用同一专用connection上的独立短
`READ COMMITTED`事务，事务前后执行关闭reset；事务安装`UTC`、有界lock/statement/
idle-in-transaction timeout、`scope_kind=SESSION_AUTHENTICATE`、
`operation=RESOLVE_COOKIE`和exact key ID/digest，随后执行唯一登记statement。零行继续
下一key；单候选多行、多个key各命中一行、数据库返回digest/key不等于候选、未知列/
enum或非UTC时间均为`SERVICE_UNAVAILABLE`并discard连接。

旧`resolve_cookie_session_v1`不读取User，不能满足本页“ACTIVE User/Family/Session图”
的完成定义。forward-only IAM 0024 migration因此发布
`iam_api.resolve_cookie_session_v2`：security-barrier/invoker view只在exact digest/key RLS
下联接同一Session、Family和User，投影v1全部字段以及关闭`user_status`，不接受actor、
User、Family或Session参数。`iam_session_authenticator`只获得v2 view SELECT；它仍不能
直接SELECT `iam.users/sessions/session_families`。User policy只允许存在exact digest/key
Session的User行，不能用caller GUC中的User ID放行。v1 bytes与语义保持不变，production
component只登记v2 statement，compatibility contract同时钉死owner、security invoker、
固定search path/无dynamic SQL、PUBLIC无权与exact列序。

一行只有同时满足以下事实才生成`AuthenticatedHttpActor`：User/Family/Session均
`ACTIVE`；`generation=current_generation`；数据库
`transaction_timestamp() < idle_expires_at`且小于`absolute_expires_at`；auth_time与全部
deadline为UTC aware；`acr_code`非空；`amr_codes`是有序、非空、无重复tuple。等号到期、
User/Family非ACTIVE、Session `EXPIRED`或generation漂移返回`SESSION_EXPIRED`；无法解释
的持久shape返回503。actor的User/Session/auth strength只来自该行，
`original_actor_id=None`；production trace source必须生成可作为持久audit ID的UUID文本，
本次普通请求的correlation/causation/trace均绑定该server trace UUID。HTTP header/body不能
覆盖这些值。

### 12.2 旧 handle replay与结果未知

exact命中`REVOKED` Session不是普通401读取。retained-key discovery必须先完成全部候选的
短只读事务并证明全局恰一命中，不能在尚未排除第二候选时先写。随后专用短写事务把
operation切换为`REVOKE_REPLAYED_FAMILY`，从该持久row安装actor/session/family、exact
key/digest与新的security command UUID；0024的固定
`iam_api.revoke_replayed_session_family_v1`程序通过
`iam.replayed_session_matches_family`重新验证该digest确实属于exact revoked Session，再按
Family→current Session顺序锁定；只有Family仍ACTIVE时才：

1. CAS撤销Family及其唯一ACTIVE current Session，reason固定为同名枚举并推进各自版本；
2. 在同一事务追加唯一`REPLAYED_SESSION_HANDLE` security-event marker；
3. 追加一条关闭SYSTEM AuditEvent；
4. 为每个真实撤销的Session追加一个schema-valid `SessionRevoked` outbox event。

该online role的新增RLS只能经已有
`iam.replayed_session_matches_family(candidate_family_id)`证明exact revoked digest所属Family；
不能仅信任GUC中的actor/session/family。security marker、audit与outbox policy还要逐字段
约束event/action/target/version/reason/关闭payload，PUBLIC无权，role不能写任意业务事件。
同一replayed Session的marker唯一；并发请求中恰一个转换Family并写事件，其他请求看到
已REVOKED后单调结束且不重复audit/outbox。raw digest、salt、cookie与CSRF不进入这些事实。

`COMMIT_SENT`断线不能被当作“旧handle无效所以无需解析”。component丢弃connection，
用新connection执行有界的同一exact-digest收敛查询：Family已REVOKED/marker已存在即完成；
Family仍ACTIVE才再次尝试单调CAS；partial/corrupt或预算耗尽为503并使component not-ready。
该resolver不是业务命令重放，不能产生第二marker/audit/outbox。无论收敛是否首次写入，旧
handle都不返回actor；安全完成后统一`AUTHENTICATION_REQUIRED`。

IAM 0024的真实门禁必须在PostgreSQL 18上覆盖fresh migrate、active/suspended
User解析、旧handle replay、双连接并发、COMMIT确认丢失后的新连接收敛，以及runtime role
直接扫描/伪造marker的RLS负例。开发机若不能运行本机`initdb`，使用隔离、loopback动态端口、
退出即删除的PG18容器运行：

```bash
cd platform
sh scripts/test_iam_session_security_pg18.sh
```

脚本不调用项目compose、不接触`postgres-data` volume，也不复用产品数据库；成功结果必须是
该文件全部13项测试通过。容器运行时不可用属于环境阻断，不能把静态测试替代成迁移放行证据。
已有一次性 PostgreSQL 18 服务时可跳过 Docker，但该服务必须允许测试 harness 创建/删除
database与closed role集，并且不能承载任何共享或持久数据。调用者必须显式确认 ephemeral：

```bash
cd platform
DESIRE_IAM_TEST_POSTGRES_DSN='postgresql://ephemeral-admin:...@127.0.0.1:6543/postgres' \
DESIRE_IAM_TEST_POSTGRES_EPHEMERAL=1 \
sh scripts/test_iam_session_security_pg18.sh
```

脚本不输出DSN；缺少`DESIRE_IAM_TEST_POSTGRES_EPHEMERAL=1`时以
`IAM_0024_TEST_EXTERNAL_POSTGRES_NOT_EPHEMERAL`和exit 78关闭拒绝。harness还会验证major
version恰为18、预期测试roles尚不存在，并在退出时删除本次database与roles。

2026-08-15已在一次性官方PostgreSQL 18.4容器上完成该门禁：13/13通过、无skip，容器由
脚本退出清理。0024 SQL raw SHA-256冻结为
`a8c11e0e9e3b48d8c3bebd5a69af66c703997882df85a97a2aec966f09cce2cb`；head24 canonical
manifest SHA-256与review pin共同冻结为
`475afb7278a051c2e1c1f0a2151471f6127af1c69d29e6bf3c3a166bcac8e6ae`。首次实跑还捕获了
test oracle把`regclass`文本当`oid`参数发送的PostgreSQL 18类型错误；harness现显式投影
`pg_catalog.oid`，随后同一13项fresh-migrate/RLS/concurrency/ACK-loss门禁全部GREEN。

### 12.3 CSRF重解析与恒定时间校验

CSRF verifier不使用进程全局或thread-local的“上一次authenticate”缓存，也不让actor
携带salt/digest。它以同一raw handle重新执行12.1的固定v2解析；只有第二次row仍为ACTIVE
且User、Session、Family、generation、auth_time/acr/amr与已返回actor逐字段一致才继续。
中间撤销/到期返回相应401，actor错绑、row shape漂移或多命中为503。

校验使用row保存的`csrf_key_id/csrf_salt/csrf_digest`：先按ADR-0004以raw handle、salt、
Session ID、generation和该exact retained CSRF key重建canonical token，再对重建token计算
持久digest并恒定时间比较row digest，以证明数据库证据未损坏；随后对请求token计算同一
digest并恒定时间比较。请求token缺失/格式错/最终不匹配为400 `INVALID_REQUEST`；row key
缺失、未知key、重建digest不一致或key purpose错误为503。CSRF keyring与Session-handle
keyring用途隔离，旧csrf key在对应Session全部终结前必须保留。`operation_id`必须属于编译
期unsafe-operation allowlist；未知operation代表composition/kernel损坏并返回503。

### 12.4 exact Origin、匿名subject与durable rate limit

production `ExactOriginPolicy`在启动时解析一个非空、无重复的canonical HTTPS origin
tuple；拒绝userinfo、path、query、fragment、`null`、通配符、大小写/尾点别名、显式默认
端口与非ASCII host。请求Origin必须与配置中的canonical字节逐字相等。只有显式synthetic
test profile可以登记canonical loopback HTTP origin；请求不能打开该开关。未知
operation或空allowlist使component not-ready；请求缺失/不匹配返回400且不产生CORS allow
header。

限速不能用单进程dict，也不能把完整IP/User-Agent写入应用。可信TLS proxy先生成带版本/
key ID的粗粒度`VerifiedNetworkBucket`（原始网络地址留在ingress安全域）；ASGI request
contract只携带其32-byte digest且`repr=False`。已认证请求的subject由rate-subject key对
User ID做用途隔离HMAC，匿名OIDC/inspect使用network bucket。production缺少匿名bucket、
声明key不可用或store不可用均503，不能allow-through。

durable limiter使用独立`iam_http_guard` role/pool和DB
`transaction_timestamp()`实现整数GCRA：row identity为
`(policy_version, operation_group, subject_kind, subject_digest_key_id,
subject_digest)`，保存下一理论到达时间、版本与更新时间，不保存IP/User-Agent/User ID。
编译期关闭表把21个operation映射到固定group、emission interval、burst和最大Retry-After；
未知operation拒绝。一次参数化fixed statement原子锁/插入/CAS并返回
`allowed,retry_after_seconds,policy_version`；失败503。拒绝只抛关闭
`RateLimitExceeded(retry_after_seconds=1..86400)`，kernel据此发送整数`Retry-After`；
普通`IamError('RATE_LIMITED')`或任意异常不得注入header。表启用FORCE RLS、online role非
owner/no BYPASS、PUBLIC无schema/table/function权限；cross-subject GUC和直接SELECT均拒绝。

ingress/WAF限速仍是第一层，不能替代上述应用级User/operation限速；应用层也不能声称靠
network bucket识别真实个人。policy调整是版本化production配置发布，不原地改历史bucket
语义。并发、窗口边界、DB clock、pool reset、key rotation、store unavailable和secret
sentinel必须用真实PG18测试。

### 12.5 web-api production composition门禁

concrete `web-api` build contract必须显式列出Session authenticator、HTTP guard、九个IAM
read programs、onboarding/self/system command UoW、OIDC/provider、presenter registry、
telemetry和ASGI entrypoint；每个database capability绑定exact role，每个密钥purpose绑定
active/retained IDs。runtime config需要发布origin/proxy/rate policy的关闭schema版本，不能
由任意环境变量或动态import补字段。

readiness在监听socket前完成：IAM schema compatibility/current contract、v2 cookie view与
replay policy、rate statement、role/ACL、全部retained Session/CSRF/rate keys、25 presenter
bindings、Origin allowlist和trusted proxy profile逐项通过。缺一项启动失败并逆序清理；
不得让kernel长期以缺port的503模式充当“已部署”。connection checkout/reset、server major、
role、TLS/channel binding与timeout沿[生产组合根](/architecture/production-composition-and-operations.md)
执行。生产entrypoint禁止test fake、Memory store、no-op telemetry、allow-all policy与
default key。

本阶段TDD顺序固定为：先冻结本5节；再以可导入default-deny adapter取得pure Origin/key/
CSRF RED和真实PG18 Session/replay/rate RED；随后仅用forward-only migration与production
adapter转GREEN；最后跑25-operation真实transport composition、浏览器cookie/CSRF和proxy
边界E2E。pure fake、旧v1 direct-SQL或单一happy cookie不能替代完成证据。

## 13. 与现有文档的关系

- OpenAPI 是 method/path、参数、关闭 DTO、响应与敏感扩展的机器事实源；本文定义字节与运行时语义，二者不一致时不得由实现暗选，必须先更新设计/契约和 RED。
- [身份、租户、政策同意与会话](/architecture/identity-tenancy-consent.md) 仍拥有角色、状态、字段可见性、Session与错误业务语义。
- [目标平台架构](/architecture/target-platform.md) 的 API/BFF 经本边界进入模块化核心；本文不改变其他 Context 的未来 API。
- [IAM PostgreSQL 实现](/architecture/iam-postgresql-implementation.md) 与 ADR-0004 拥有 receipt、RLS、事务和 COMMIT unknown 事实；HTTP 只保持其结果。
- [Outbox 投递](/architecture/outbox-delivery.md) 不在请求事务中同步 publish，HTTP response 也不等待 broker ack。
