# INTERNAL_SANDBOX ACCESS_ADMIN 账号管理工作台

> 状态：`IMPLEMENTED / AUTOMATED GREEN / FRESH-STACK BROWSER E2E PENDING`
> 适用范围：最多 16 个 active synthetic identity bootstrap 账号。
> 不授权：真人研究、公开注册、真实联系方式、组织授权管理、真实合同/资金或公开服务。

## 1. 用户结果与唯一真相源

`ACCESS_ADMIN` 合成账号可在平台职责工作区查看 bootstrap 账号列表和详情，暂停/恢复其他
合成账号，撤销其全部会话，并为其他合成账号授予或撤销五种关闭的平台职责：
`ACCESS_ADMIN`、`OPERATIONS_REVIEWER`、`FINANCE_OPERATOR`、`TRUST_OFFICER`、
`APPEAL_REVIEWER`。账号、Session、SessionFamily 与 platform duty grant 继续只由现有 IAM
事实管理；本切片不新增第二套账号表、会话表或浏览器角色真相源。`CREATOR`、
`DEMAND_OWNER`、`ORG_ADMIN` 仍由邀请/政策/成员关系约束，本工作台不能配置。

生产路径只接受 PostgreSQL。不存在 Memory/no-op repository、production fixture fallback、
客户端自授 authority 或“页面先成功、稍后再写库”的路径。退出或刷新浏览器后，页面重新
读取 IAM 投影。

## 2. HTTP 与关闭投影

正式产品边界为：

```text
GET  /v1/app/admin/accounts
GET  /v1/app/admin/accounts/{user_id}
POST /v1/app/admin/accounts/{user_id}/suspend
POST /v1/app/admin/accounts/{user_id}/resume
POST /v1/app/admin/accounts/{user_id}/revoke-all-sessions
POST /v1/app/admin/accounts/{user_id}/platform-duties/{duty_code}/grant
POST /v1/app/admin/accounts/{user_id}/platform-duties/{duty_code}/revoke
```

读请求不接受 body。写请求要求当前 `If-Match`、独立 `Idempotency-Key`、同源 CSRF，并且
body 精确为一个关闭理由：

```json
{"reason_code":"ACCESS_REVIEW | SAFETY_REVIEW | SESSION_HYGIENE"}
```

body/header 不接受 actor、organization、role、duty 或 authority；actor、Session 与所选
workspace 由认证边界注入。`duty_code` 只能出现在 exact path，且只能取上述五值。BFF 只转发
上述 exact path/method 和既有安全 header allowlist，拒绝 query、未知 action、错误方法、零
UUID 与非规范 UUID。

列表/详情只返回：

```text
account_code, user_id, display_handle, status,
aggregate_version, entity_tag, sorted role_codes,
active_session_count, created_at, updated_at, is_self
```

不返回 email/phone、OIDC issuer/subject、identity/contact digest、receipt material、
Organization membership/role 或其他账号的 Session ID。列表按 `account_code` 排序，精确
一个 `is_self=true`，账号数必须在 1..16，否则整次读取 fail closed。

## 3. IAM0027/IAM0030/IAM0032 fixed read 与 RLS

forward-only IAM `0027` 首先新增一个 `iam_app` 可执行的固定 read program：

```text
iam_api.read_internal_sandbox_account_workbench_v1(
  actor_user_id uuid,
  current_session_id uuid,
  target_user_id uuid|null
) -> jsonb
```

调用必须是 PostgreSQL 18、`iam_app`、`REPEATABLE READ READ ONLY`，并逐字读回 actor、
Session、target 与空 Organization GUC。数据库独立重验 active synthetic bootstrap、当前
User/Session/SessionFamily generation/expiry 和有效 `ACCESS_ADMIN` duty；仅匹配 bootstrap
的 User、Session 与 duty rows 可经 schema-owner FORCE-RLS policy 读取。PUBLIC、其他 online
role 和 bootstrap role 均无函数执行权或直接表读取权。

无 duty、过期/撤销 SessionFamily、User suspension、伪 GUC、错误 runtime role、bootstrap
漂移、多重/缺失 active state、超出 16 账号或字段不闭合全部转为不可用；未知 target 只返回
404，不泄露相邻账号。

IAM `0030` 新增 `read_internal_sandbox_account_workbench_v2`。V2 使用 LEFT JOIN/空数组投影，
因此撤销某账号最后一个 duty 后，该 synthetic bootstrap 账号仍可见；最多接受三种绑定角色与
五种平台职责的关闭并集。0027 及其 V1 函数字节保持历史冻结，不原地改写。

冻结 pin：0030 SQL SHA-256
`ac3806b839c3aebfaf8540612a5c09dffc1be1afc6f4c5db4cf0eb31c8fb1bd9`；IAM0030 快照
manifest SHA-256 `bd5bc355d03ee0878b250925ec0bd03a14325e36091050ea2e1b499840a55ac5`。
后续 migration 只能 forward-only 追加，不能修改 0030 或更早历史字节。

IAM `0032` forward-only 收紧了历史账号生命周期写边界：`suspend`、`resume` 与
`revoke-all-sessions` 在 receipt claim 前先锁定当前 bootstrap revision，并要求 actor 与 target
都属于唯一 active synthetic bootstrap；旧通用 v1 lock 对 `iam_app` 的执行权已撤销，User、
SessionFamily、Session 与 receipt 的 permissive RLS policy 全部替换为 synthetic-only v2，不能
通过直接 SQL 绕过固定程序。bootstrap 写与管理写共同取得固定 advisory lock，revision
rotate/revoke 不能与账号写交错。

同一 actor、command 与 idempotency digest 的冲突由只返回 boolean 的 SECURITY DEFINER probe
按完整 command scope 检测；probe 不返回旧 target、payload 或 safe response。跨 target 或跨
duty 复用 key 稳定返回 `IDEMPOTENCY_KEY_REUSED`，而合法精确重放只校验历史 receipt 自洽，
target 后续版本或状态变化不会破坏原响应。职责重授若遇到 expired-but-unrevoked 历史行，会在
同一事务内固定收敛为 `EXPIRED_SUPERSEDED` 后插入新 grant；未来生效或其他未撤销行直接拒绝，
不把唯一索引异常泄漏为 503。

冻结 pin：0032 SQL SHA-256
`c5bcb3466dc9f8c64995c1a7008eef9651e12b10ac29e65735e7a61eb233c5c9`；IAM head 32 canonical
manifest SHA-256
`0f1dff47f4b814c6e319fd3f9297ce0922538294c9b63a77cf9694f159e711b6`。0030/0031 及更早
bytes 未改写。

## 4. 写事务、OCC 与 receipt key

写入复用 IAM0018 已有 `PsycopgPlatformUserLifecycleUnitOfWorkFactory`，使用同一个
`iam_app` role-bound pool；不复制 suspend/resume/session revoke SQL。每笔命令绑定 exact
target User version、canonical method/path/body、actor/Session、命令/审计/outbox ID 和
receipt。事务内完成 User/Session graph lock、state transition 或 session-family revoke、
append-only audit、outbox、receipt completion 后才提交。

IAM0030 在同一 UoW 增加 `GrantPlatformDuty`/`RevokePlatformDuty`。数据库固定重验 active
synthetic bootstrap、非 self target、active `ACCESS_ADMIN`、最近十分钟 MFA、Session 与
SessionFamily；再锁定管理员集合、target User 和 exact duty grant。职责变化与 target User
version CAS、`PlatformDutyGrant` audit、`PlatformDutyGranted/Revoked` outbox 和 receipt 在同一
事务提交。客户端传入的 role/authority 不参与授权，也不存在直接 DELETE grant 的路径。

管理员不能管理自己；last active ACCESS_ADMIN、非法状态迁移、stale ETag、撤销 duty、
receipt payload/key 冲突均由数据库拒绝。COMMIT acknowledgement loss 返回
`COMMAND_OUTCOME_UNKNOWN`，调用方只能重放同一 idempotency key 与逐字相同请求。

receipt 使用两份独立 stable material，不能与现有 key alias：

```text
iam-receipt-idempotency-hmac-2026-01
iam-receipt-payload-hmac-2026-01
```

部署 bundle 因此固定为七个数据库 credential + 十七个 purpose key，共 24 secret。key
material 的 repr/log 必须 redacted；轮换保留旧 row-bound key 直到 retention window 关闭。

## 5. Web 恢复语义

只有服务端发现的 `PLATFORM + ACCESS_ADMIN` workspace 才请求账号 collection 和显示账号
入口，非管理员浏览器不会探测该 API。详情中的按钮按服务端状态和有效 duty 显示；self target
的状态、会话和 duty 操作全部禁用。没有有效角色或 duty 的 synthetic 账号仍显示为“无有效职责”。

浏览器 pending record 只保存关闭 write intent，并绑定 target UUID、ETag、CSRF、相同
idempotency key 和 reason。网络/5xx 时保留“原样重试”；明确 4xx/412 时清除 pending，要求
刷新详情后生成新 intent。命令响应必须通过关闭 parser 且 body ETag 与响应 header 一致；
命令确认后即清除 pending，再读取 IAM 详情，避免详情刷新故障错误重放已确认命令。fresh GET
必须同时绑定所请求 `user_id`、HTTP/body ETag，且版本不得落后于已确认命令。

## 6. RED → GREEN 与剩余动态门禁

- application/HTTP：列表/详情闭合、三账号 action、五 duty 的 grant/revoke、OCC/idempotency、
  无 authority input、非管理员 404、production fixed UoW 和 key redaction；
- PostgreSQL 18：fresh apply、grant/revoke 第二次与延迟 exact replay、跨 target/duty IDK 冲突、
  expired regrant、future grant fail-closed、三个非 bootstrap 生命周期写零落账、roleless
  列表/详情、unknown target 与既有六账号 bootstrap/Finance regression；
- Web/BFF：关闭 parser、pending expiry/recovery、exact route allowlist、非法 query/action/header、
  ACCESS_ADMIN gating、build/typecheck/lint；
- deployment/package：forward-only IAM catalog/manifest、Demand compatibility、关闭 key/secret
  composition、Compose 静态合同与文档导航。

自动门禁已 GREEN。正式本地分角色结论仍等待新的独立 Compose project 完成 fresh-stack
apply/exact replay、隔离浏览器 profile、duty grant→fresh read→revoke、暂停→恢复→撤销会话、
stale ETag、旧 cookie 失效和重启恢复。操作清单见
[本地运行与逐步操作检查指南](/operations/run-and-check.md#45-十账号浏览器账号管理与职责隔离)。
即使动态验收通过，环境仍是 `INTERNAL_SANDBOX / G1 NO-GO / G2 NO-GO`，不得发布到
OpenAI Sites。
