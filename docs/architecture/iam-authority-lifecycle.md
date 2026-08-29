# IAM 权限、consent 与 Session 生命周期命令

> 状态：IAM-01 权威补充设计及 Memory application 实现已完成；`TEST-APP-INVITATION-REVOKE-001`、`TEST-APP-CONSENT-WITHDRAW-001`、`TEST-APP-SESSION-LIFECYCLE-001`、`TEST-AUTH-SESSION-REPLAY-001` 与三个 Membership lifecycle TEST 共 `38/38` GREEN。后续 IAM42 另已实现 PostgreSQL-backed `UpdateOrganizationPublicName`；本页未声称其他 IAM-01 Memory 命令因此自动获得 PostgreSQL 证据。

## 1. 目的、边界与裁决

本文补齐[身份、租户、政策同意与会话设计](/architecture/identity-tenancy-consent.md)中七个公开组织/生命周期 operation，以及旧 Session handle replay 的内部安全命令：

- `RevokeAccessInvitation`；
- `WithdrawConsentGrant`（OpenAPI operationId 仍为 `withdrawConsent`）；
- `RevokeSession`（`DELETE /v1/me/sessions/{session_id}`，包含当前浏览器 logout 结果）；
- `SuspendMembership`、`ResumeMembership`、`RevokeMembership`；
- `UpdateOrganizationPublicName`（`POST /v1/organizations/{organization_id}/public-name`）；
- `RevokeReplayedSessionFamily`，它不是新增 HTTP operation，而是 Session authenticator 检测到旧 handle 后的内部协议动作。

前六个 IAM-01 公开命令不新增角色、状态、事件类型或 PostgreSQL migration。`UpdateOrganizationPublicName` 是后续 IAM42 窄扩展：它只允许更正公开名称，不允许改 Organization ID、type、status、jurisdiction、Membership 或 role，并新增关闭事件 `OrganizationPublicNameChanged`。机器 API 仍以 `platform/contracts/api/iam-v1.openapi.yaml` 为准，事件仍以 `platform/contracts/events/iam-v1.schema.json` 为准。

冲突时，[ADR-0003](/decisions/0003-oidc-bff-session-and-protocol-exceptions.md)决定 Session/协议例外，[ADR-0004](/decisions/0004-iam-onboarding-persistence-and-postgres.md)决定 receipt、family、hold 与 PostgreSQL 执行协议，本文只把这些规则关闭到可实现的命令级别。

设计审计作出以下裁决：

1. 权限减少与隐私撤回不能依赖 SafetyHold；只有 `ResumeMembership` 是恢复权限，必须以 exact Membership ID/version 在事务外取得短期 hold 决定。
2. 公开 invitation revoke 只管理 `ORGANIZATION_MEMBERSHIP` 邀请。当前同组织 ACTIVE ORG_ADMIN 可以撤销，不要求仍是原 issuer；原 issuer 失去当前权限后没有旁路。PENDING_ADMIN initial-admin 与 creator invitation 只允许已有内部 SYSTEM 编排处理，不通过此公开 operation。
3. Membership suspend 不撤销全局 Session；Membership gate 在事务提交后立即使该 Organization 的授权失败。Membership revoke 还在同一事务撤销 IAM-01 唯一的未撤销 MembershipRoleGrant。Resume 保留该原 role，不产生新 role grant。
4. logout/revoke 只终结 exact Session；旧 handle 重放才终结 exact SessionFamily 及其中仍 ACTIVE 的 successor。`SessionsRevoked` 代表所有 family，不可误用于单 family replay。
5. 同一 completed receipt 的重放在任何领域守卫前识别，但返回含组织管理资料的安全 DTO 前仍重新证明当前 Session、same-org ORG_ADMIN 和 recent MFA；重放不重新执行 hold、不产生第二份 audit/outbox，也不恢复终态。
6. 关系/租户不成立时先返回不可披露的 `RESOURCE_NOT_FOUND`；只有关系已经证明后才暴露 `PRECONDITION_FAILED`、`INVALID_STATE_TRANSITION` 或 `LAST_ACTIVE_ORG_ADMIN`。

## 2. 稳定设计与测试标识

| DESIGN | 对应要求 | 冻结结果 | TEST |
| --- | --- | --- | --- |
| `DES-AUTHORITY-INVITATION-001` | `REQ-IAM-003`、`REQ-IAM-005`、`REQ-HOLD-IAM-001` | same-org admin 撤销 exact ISSUED organization invitation；无 hold；DTO/event/receipt 原子 | `TEST-APP-INVITATION-REVOKE-001` |
| `DES-AUTHORITY-CONSENT-001` | `REQ-CONSENT-002`、`REQ-PRIVACY-IAM-001` | 本人追加 Withdrawal 并终结 exact Grant；不删除历史、不调用 hold | `TEST-APP-CONSENT-WITHDRAW-001` |
| `DES-AUTHORITY-SESSION-001` | `REQ-SESSION-002`、`REQ-IAM-004` | 本人 exact Session 单调终结；当前 logout 清 cookie；无 If-Match | `TEST-APP-SESSION-LIFECYCLE-001` |
| `DES-AUTHORITY-SESSION-002` | `REQ-SESSION-002`、`REQ-AUDIT-IAM-001` | 已验证旧 handle replay 原子撤销 exact family/current successor | `TEST-AUTH-SESSION-REPLAY-001` |
| `DES-AUTHORITY-MEMBERSHIP-001` | `REQ-TENANT-001`、`REQ-TENANT-002`、`REQ-HOLD-IAM-001` | same-org admin + recent MFA + last-active-admin；仅 resume 调 hold | `TEST-APP-MEMBERSHIP-SUSPEND-001`、`TEST-APP-MEMBERSHIP-RESUME-001`、`TEST-APP-MEMBERSHIP-REVOKE-001` |
| `DES-AUTHORITY-ORGANIZATION-NAME-001` | `REQ-TENANT-001`、`REQ-TENANT-002`、`REQ-API-IAM-001` | same-org ACTIVE ORG_ADMIN + recent MFA；只更正关闭公开名称；Organization ETag/receipt/audit/outbox 原子 | IAM42 contract/application/HTTP/PostgreSQL/Web 纵向测试 |
| `DES-AUTHORITY-ATOMIC-001` | `REQ-DB-IAM-001`、`REQ-AUDIT-IAM-001` | receipt、状态、audit、关闭 outbox 同事务；commit unknown 不猜测 | 上述全部 TEST |
| `DES-AUTHORITY-PRIVACY-001` | `REQ-PRIVACY-IAM-001`、`REQ-API-IAM-001` | raw key、cookie、handle/digest、contact、reason note 不进入持久安全边界 | 上述全部 TEST 的 secret sentinel |

这些 ID 不替代原要求；它们给已有要求提供命令级唯一实现协议。

## 3. 关闭命令与权威 actor

### 3.1 公共 metadata

所有公开命令使用版本 `1`，actor 只能由认证层建立，至少包含：

```text
LifecycleActorContext
  actor_user_id
  current_session_id
  original_actor_id?
  correlation_id
  causation_id
  trace_id
```

客户端不能提交 actor、organization、Membership、role、MFA、Session family、hold target、事件或响应字段。application 先通过 current raw cookie 的版本化 digest 定位 Session，随后只信任持久 User、SessionFamily、Session、Membership 与 role grant。当前 Session 必须满足：

- User、SessionFamily、Session 均为 `ACTIVE`；
- `family.current_generation == session.generation`；
- Session user 恰为 actor；
- 所有时间为 aware UTC，且 `server_now < idle_expires_at`、`server_now < absolute_expires_at`；等号已失效；
- 对组织管理命令，`acr/amr` 满足 `iam-security-v1` MFA policy，且 `server_now - auth_time < 10 minutes`；未来 auth_time、缺字段、naive/非 UTC 或 deadline 等号均为 `MFA_STEP_UP_REQUIRED` 或持久事实损坏时的 `SERVICE_UNAVAILABLE`，不读取 context 自报值。

### 3.2 命令 shape

```text
RevokeAccessInvitationCommand
  invitation_id
  expected_version              # Invitation If-Match
  idempotency_key
  reason_code
  reason_note?

WithdrawConsentGrantCommand
  consent_grant_id
  expected_version              # ConsentGrant If-Match
  idempotency_key
  reason_code
  reason_note?

RevokeSessionCommand
  session_id
  idempotency_key               # no If-Match and no client reason body

SuspendMembershipCommand | ResumeMembershipCommand | RevokeMembershipCommand
  membership_id
  expected_version              # Membership If-Match
  idempotency_key
  reason_code
  reason_note?

UpdateOrganizationPublicNameCommand
  organization_id
  expected_version              # Organization If-Match
  public_name
  reason_code = PUBLIC_NAME_CORRECTION
  idempotency_key

RevokeReplayedSessionFamilyCommand     # internal protocol command
  security_event_id             # authenticated, opaque causation/idempotency fact
  replayed_session_id
  session_family_id
  user_id
```

`reason_code` 按 OpenAPI `ReasonCode` 关闭校验。`reason_note` 只用于当前请求的人类操作上下文：关闭长度/Unicode 后不得进入 receipt、AuditEvent、outbox、日志或 trace；首切片不具有批准的 A 层 reason-text evidence store，因此服务端不持久化正文，只保存 reason code。客户端不知道该限制不能把 note 当成授权或重放事实。

`RevokeSession` 的持久原因由服务端按 target 推导为 `USER_LOGOUT_CURRENT_SESSION` 或 `USER_REVOKED_SESSION`。family replay 固定为 `REPLAYED_SESSION_HANDLE`。这些值不由请求 body 覆盖。

## 4. 单命令领域语义

### 4.1 RevokeAccessInvitation

执行者必须是当前 ACTIVE User，经 ACTIVE current Session/family 认证，并具有 invitation.organization_id 下 ACTIVE Membership 与未撤销 ORG_ADMIN grant。Organization 必须 ACTIVE，Invitation 必须：

- `purpose=ORGANIZATION_MEMBERSHIP` 且 organization_id 非空；
- 当前状态 `ISSUED`；
- If-Match 恰等于 aggregate version；
- issuer 可以是该 User、另一名当时/当前 admin 或 SYSTEM bootstrap；当前关系始终优先，历史 issuer 不授予权限。

成功写 `ISSUED -> REVOKED`、server `terminal_at/reason_code`、version `+1`。终态不可恢复。跨组织、creator invitation、PENDING_ADMIN internal invitation 或 actor 无当前管理员关系统一 404；已证明 same-org 后的 ACCEPTED/REVOKED/EXPIRED 为 409 `INVALID_STATE_TRANSITION`。

成功响应必须是 contract-valid `AccessInvitationAdminDto`。masked recipient 只能使用已存安全 mask；不得为响应解密 locator。`required_policy_bundle_id` 使用 invitation 已存 selector 的当前有效公开投影；本命令不得按 role/locale 重算 selector。

### 4.2 WithdrawConsentGrant

actor 必须是 grant.user_id，且使用自己的当前 ACTIVE Session。它不要求当前 policy acceptance、MFA、Organization relationship 或 SafetyHold。服务端锁 exact ConsentGrant 与可能存在的 Withdrawal：

- `ACTIVE` 且未到 expires_at：追加唯一 ConsentWithdrawal，Grant 转 `WITHDRAWN`，version `+1`；
- deadline 已到或已物化 `EXPIRED`：已无未来 authority，same completed receipt 可重放；新命令返回 409 `INVALID_STATE_TRANSITION`，不伪造 withdrawal；
- 已 `WITHDRAWN`：只有 exact completed receipt 可重放；新 key 返回 409；
- 另一 User、缺失 grant 统一 404。

成功从 transaction timestamp 起停止该 purpose/scope 的未来处理，不删除 ConsentGrant、PolicyAcceptance、合同、付款、争议或 audit，不影响其他 consent、Membership 或 Session。响应只投影 `ConsentGrantDto` 的公开 recipient label；内部 recipient ref 与认证 evidence 不出边界。

### 4.3 RevokeSession 与当前 logout

actor 可管理且只能管理 user_id 与自己相等的 Session。目标 ID 不存在或属于另一 User统一 404；不要求 If-Match，也不因 aggregate version 漂移阻止撤销。

- target 为 ACTIVE 且两个 deadline 仍开放：写 `REVOKED`、server revoked_at/reason、version `+1`；
- target 已 `REVOKED` 或有效上已过期：返回相同 204 终态。exact completed receipt 为零写重放；新 key 可以建立一个 204 receipt 与最小 `ALREADY_TERMINAL` audit，但不得再次变更 Session或发第二个 `SessionRevoked`；
- target 为 ACTIVE 但 `server_now` 已达到 idle/absolute deadline：同事务物化 `EXPIRED` 后返回 204，不发声称 REVOKED 的事件。

目标等于 current session 时结果标记 `clear_current_session_cookie=true`，HTTP 边界清除 `__Host-ds_session`；响应正文为空。删除另一 family 的 Session 不轮换或撤销当前浏览器 Session。SessionFamily 可以在没有 ACTIVE Session 时保持 ACTIVE；旧 handle 永不恢复。

### 4.4 旧 handle family replay

只有 Session authenticator 已用 exact retained handle-digest key恒定时间匹配到一条终态 Session，才能构造内部 replay command；body、header或普通 application caller不能自报 replay evidence。原始 handle、digest、key material和 cookie不传入生命周期 handler或审计。

固定事务锁 exact family 与全部 Session：若 family 仍 ACTIVE，则把 family 置 REVOKED/version `+1`，并把该 family 中仍 ACTIVE 的 successor 全部置 REVOKED。每个新终结的 Session 产生一个 contract-valid `SessionRevoked`；没有新终结 Session 时只追加最小安全 audit。不得发 `SessionsRevoked`，因为该 schema 表示 User 的所有 ACTIVE families。相同 `security_event_id` 或已 REVOKED family 重放不产生第二事件。

### 4.5 Membership lifecycle

共同守卫为：ACTIVE Organization；actor/Session authority 满足 3.1；actor 是同组织 ACTIVE Membership 且有未撤销 ORG_ADMIN grant；target Membership 的 organization 恰相等；reason 有效。原 issuer、账号角色、另一 Organization 的 ORG_ADMIN、body 自报 organization 或 role 都不授权。

active admin 的定义恰为：`Membership.status=ACTIVE` 且同一 Membership 下存在 `role_code=ORG_ADMIN AND revoked_at IS NULL`。计数与 target/role 变更在同一 Organization 锁下完成。

| 命令 | target 状态 | 结果 | last-active-admin | hold |
| --- | --- | --- | --- | --- |
| Suspend | ACTIVE | Membership → SUSPENDED，version +1；role grants 不变 | target 是 active admin 且 count <= 1 时 `LAST_ACTIVE_ORG_ADMIN` | 不调用 |
| Resume | SUSPENDED | Membership → ACTIVE，version +1；复用仍未撤销且合法的 roles | N/A；恢复不会减少 active admin | exact target/version 的 ALLOW 必需 |
| Revoke | ACTIVE 或 SUSPENDED | Membership → REVOKED，version +1；IAM-01 唯一未撤销 MembershipRoleGrant 同事务 revoke/version +1 | 只有 target 当前是 active admin 且 count <= 1 时阻止；SUSPENDED target 不计 active admin | 不调用 |

同一 actor 可以 suspend/revoke 自己，但不得移除最后 active admin；提交后该 Organization 的当前 actor authority 立即消失。IAM-01 的单角色邀请与 `(organization_id,user_id)` 唯一关系意味着一个 Membership 恰有一个role grant。Resume要求它仍未撤销且属于`ORG_ADMIN | DEMAND_OWNER`：exact grant已撤销是409 `INVALID_STATE_TRANSITION`；整条grant缺失、关系错绑或出现多条候选是503 `SERVICE_UNAVAILABLE` 的持久事实损坏。未来 `GrantMembershipRole` 若允许多角色，必须先扩展关闭事件与 outbox 唯一约束，不能让本 handler按当前 singular payload猜测。REVOKED 终态不能 resume。same-org 已证明后的错误源状态为409。

现有 `MembershipAdminDto.roles` 要求至少一项。对 REVOKED 响应，它投影本次终结前的最后一组安全 role labels，用来解释管理结果；这些 labels 不是 ACTIVE grant，不可再参与授权。数据库中的对应 role grants 已在同一事务写入 revoked_at/reason/version。

### 4.6 Organization public name 更正

执行者必须是 ACTIVE User，使用 ACTIVE current Session/Family 且 generation 一致；Organization 必须为 `ACTIVE`，actor 必须在 path 指定的同一 Organization 中拥有 ACTIVE Membership 和未撤销 `ORG_ADMIN` grant。`DEMAND_OWNER`、另一组织的管理员、暂停/撤销成员、过期 Session 或客户端自报角色都不授权。MFA 必须满足 3.1 节且 `server_now - auth_time < 10 minutes`；等于十分钟已过期。

body 恰为 `{public_name, reason_code}`，`reason_code` 固定为 `PUBLIC_NAME_CORRECTION`。`public_name` 必须已经 NFC 规范化、与自身 trim 结果逐字相等、含 1..160 个 Unicode code point，且不得含 Unicode category `Cc` 或 `Cf`。应用与数据库双重校验同一边界；不会为用户自动 trim 或 normalize。

新命令必须带当前 Organization strong `If-Match` 与独立 `Idempotency-Key`。exact completed receipt 在“新名称与当前名称相同”检查前重放；receipt miss 且名称未变时返回 `409 INVALID_STATE_TRANSITION`，不创建空更新。stale Organization ETag 返回 `412 PRECONDITION_FAILED` 并附当前 Organization ETag。成功只更新 `public_name`、`updated_at` 和 Organization `aggregate_version + 1`，返回新 `OrganizationSummaryDto` 与同源 ETag。

邀请 inspect 不保存组织名称快照；它在每次匿名预览时以 exact Invitation 实时 join `iam.organizations.public_name`。因此合法更正提交后，已签发且尚可检查的邀请立即显示新名称，但 Invitation ID、aggregate version、ETag、token/capability 和政策绑定全部不变；这不是邀请修订或重签发。

## 5. SafetyHold 唯一协议

`RevokeAccessInvitation`、`WithdrawConsentGrant`、`RevokeSession`、family replay、`SuspendMembership`、`RevokeMembership` 和 `UpdateOrganizationPublicName` 不调用 SafetyHold。测试 fake 即使配置 BLOCK、UNAVAILABLE 或抛出定义异常，call count 必须保持零；其他授权守卫仍执行。

`ResumeMembership` 在 receipt miss 且事务外 snapshot 已通过结构/authority 检查后调用：

```text
action = ResumeMembership
target_type = Membership
target_id = exact membership_id
target_version = snapshot aggregate_version
organization_id = target.organization_id
policy_version = configured immutable version
```

只接受逐字段相等且 `evaluated_at <= server_now < valid_until` 的 ALLOW。BLOCK → 403 `SAFETY_HOLD_BLOCKED`；UNAVAILABLE、错 action/type/id/version/org/policy、未来 evaluated_at、过期/等号或定义的 provider unavailable → 503 `SAFETY_DECISION_UNAVAILABLE`，且 UoW/receipt/audit/outbox 零写。

写事务锁后 target version、Organization、actor authority、target roles或任一 hold 依赖 snapshot 漂移时，回滚并释放全部锁，再在事务外用新 snapshot重新 evaluate；旧 ALLOW不能复用。重评有有界次数，耗尽返回 `PRECONDITION_FAILED`，不能持锁调用 provider。

## 6. receipt、If-Match 与重放

公开命令沿用五元 receipt identity：

```text
(USER, actor_user_id, command_name, command_version=1,
 idempotency_key_digest)
```

raw Idempotency-Key 不落库。payload HMAC 覆盖关闭 method/path、target kind/ID、If-Match（Session 为 null）、command/schema version 与请求体；reason note 先用独立受限 digest替代，不能把原文放 canonical bytes、receipt或异常。Cookie、CSRF、trace、MFA facts不属于 payload。

IAM42 还把同一 actor 的 raw key 在 `IssueAccessInvitation`、`RevokeAccessInvitation`、三个 Membership 命令与 `UpdateOrganizationPublicName` 之间关闭为同一 ORG_ADMIN family。当前 key digest 由 partial unique index 防重，retained-key candidates 由窄函数逐项解析；同 raw key 跨 operation 必须返回 `IDEMPOTENCY_KEY_REUSED`，不能因换 key ID 而绕过。

处理顺序关闭如下：

1. 验证输入、当前 Session和全部 retained receipt/session key material；任一缺失在 UoW/SafetyHold 前以 `SERVICE_UNAVAILABLE` 零写。
2. 以当前 principal/command/key查 exact receipt。same key/different hash → 409 `IDEMPOTENCY_KEY_REUSED`；IN_PROGRESS → 稳定 conflict；COMPLETED 进入安全重放。
3. Invitation/Membership/Organization safe DTO 重放重新证明当前 same-org ORG_ADMIN、recent MFA 与 target relationship；Consent/Session 重放重新证明当前 User 是原 principal/target owner。重放不重新检查旧 If-Match、旧 terminal state或 SafetyHold，不写第二条记录。
4. miss 才执行新命令。Invitation、Consent、Membership 与 Organization 必须在关系证明后比较 If-Match；stale → 412 `PRECONDITION_FAILED` 且零写，Organization 更名还返回 typed 当前 ETag。Session 明确没有 If-Match。

receipt 与安全响应逐字段绑定 target/version：Invitation=`AccessInvitationAdminDto`、Consent=`ConsentGrantDto`、Membership=`MembershipAdminDto`、Organization=`OrganizationSummaryDto`、Session=`{}` 的内部 204 schema。以上命令都没有 secret reconstruction metadata。safe response、target、principal、command、schema 或当前持久事实不一致为 503 `SERVICE_UNAVAILABLE`，不猜测重建。

## 7. 固定事务与锁序

provider/KMS/SafetyHold 不得位于 UoW 或数据库 retry closure。read-only preflight 不是授权；所有事实在锁后重验。IAM-01 命令的 receipt identity row先 claim；IAM42 ORG_ADMIN 共享程序为了与原有组织命令保持锁序，先锁组织权威图再执行六命令 retained receipt 解析。同层多行按 UUID bytes 排序，重复行只锁一次：

| 命令 | `SELECT ... FOR UPDATE` 顺序 |
| --- | --- |
| Invitation revoke | receipt → actor SessionFamily → actor Session → actor User → Invitation → Organization → actor Membership → actor ORG_ADMIN grant → selector/current public projection |
| Consent withdraw | receipt → actor SessionFamily → actor Session → actor User → ConsentGrant → existing ConsentWithdrawal |
| Session revoke | receipt → User → 涉及的 SessionFamily（排序）→ actor/target Session（排序） |
| Family replay | security event identity → exact SessionFamily → family Sessions（排序） |
| Membership actions | receipt → actor SessionFamily → actor Session → actor User → Organization → actor Membership → actor ORG_ADMIN grant → target Membership → target role grants（排序）→ active-admin Membership集合（排序）→对应 ORG_ADMIN grants（排序） |
| Organization public name | Organization →该 Organization Memberships（排序）→ MembershipRoleGrants（排序）→ actor Session → SessionFamily → User → six-command retained receipt candidate |

所有能创建/撤销 MembershipRoleGrant 的后续命令必须先锁 Organization，再参与相同 active-admin集合协议，否则不能证明 last-admin 不变量。

一次新成功命令在一个 READ COMMITTED 本地事务中完成：IN_PROGRESS receipt、领域状态、必要 child状态、AuditEvent、全部 outbox、COMPLETED receipt。任一 schema validator、safe-response validator、约束或定义的 storage fault 失败，全部回滚且不留 IN_PROGRESS receipt。

只有 COMMIT 尚未发送、没有外调/外部副作用的短事务可按 ADR-0004 对 `40001/40P01/55P03` 有界重试。发送 COMMIT 后任一异常只返回 503 `COMMAND_OUTCOME_UNKNOWN`；server 不在同一请求重执行。客户端以同 key查询 receipt：存在则安全重放，不存在才重新执行。

## 8. 即时授权效果

- Membership SUSPENDED/REVOKED 提交后，所有 Organization authorization 每次读取 current Membership/role，立即拒绝该 Organization；不等待 outbox、cache TTL或 Session到期。
- Membership suspension 不改变其他 Organization、UserRole、Consent或全局 Session。Resume 只恢复该 Membership gate。
- Membership revoke 使其所有 role grant 同事务失效；下游事件只是通知，不是授权事实源。
- Session REVOKED/EXPIRED 提交后，handle verifier立即拒绝；本地缓存必须以 Session/family aggregate version或撤销 watermark失效，不能继续离线授权。
- current logout只清当前 cookie；另一 Session/family不受影响。old-handle replay只撤销命中的 exact family；User suspension才是全部 family。
- consent withdrawal提交后依赖方在实际动作前必须查询/验证 current consent version；outbox延迟不能延长授权。

## 9. 关闭 audit、outbox 与安全 DTO

每次真实状态转换追加一条命令 AuditEvent；Membership revoke 同一 audit可关联多个 role事件。audit只使用关闭列：actor/original actor、action、target、organization、before/after status/version、role/purpose、reason code、auth strength、result、command/correlation/causation/trace和server time。`reason_note`、contact、recipient ref、Session digest、cookie/CSRF、idempotency key/payload hash、hold provider正文不进入 audit/safe_attributes。

outbox 必须逐项通过 `iam-v1.schema.json`，只使用：

| 转换 | 关闭事件 |
| --- | --- |
| Invitation → REVOKED | 一个 `AccessInvitationRevoked`；aggregate=Invitation新版本；creator/org binding分支与 organization_id严格匹配，本公开命令只产生organization分支 |
| ConsentGrant → WITHDRAWN | 一个 `ConsentWithdrawn`；payload使用既存关闭 derived authorization，不含 recipient ref/label或evidence |
| Session → REVOKED | 一个 `SessionRevoked`；organization_id=null；payload只含session/family/user/status |
| Membership → SUSPENDED | 一个 `MembershipSuspended` |
| Membership → ACTIVE | 一个 `MembershipResumed` |
| Membership → REVOKED | 一个 `MembershipRevoked`，另为本切片唯一 role grant产生一个 `MembershipRolesRevoked`；多角色支持先改机器契约 |
| Organization public name 更正 | 一个 `OrganizationPublicNameChanged`；aggregate=Organization 新版本，payload 恰为 `{organization_id}` |

相同 completed receipt、already-terminal Session或already-revoked family不产生第二 outbox。事件共享命令 correlation/causation/original actor但各有 event_id。任何额外字段、错误 aggregate/version/org绑定或递归 secret sentinel使整个新执行事务回滚。

Organization 公开名称的 audit `safe_attributes` 为空对象，outbox payload 只有 `organization_id`；两者都不存旧名称或新名称。为支持 exact replay，completed receipt 的关闭 `OrganizationSummaryDto` 安全响应会包含当时提交的 `public_name`，但不包含旧名称、自由文字或 reconstruction metadata。

响应严格使用现有 OpenAPI DTO；Session为204无 body。`AccessInvitationAdminDto`不返回 issuer内部身份、contact或token；`ConsentGrantDto`不返回recipient ref/auth evidence；`MembershipAdminDto`不返回contact/ExternalIdentity；任何 DTO均不返回reason note、receipt/audit/outbox metadata。

## 10. 错误与非披露顺序

| 条件 | 稳定结果 |
| --- | --- |
| current Session缺失/失效 | 401 `AUTHENTICATION_REQUIRED` 或 `SESSION_EXPIRED` |
| target不存在、跨User/跨组织、actor无可披露关系 | 404 `RESOURCE_NOT_FOUND` |
| same receipt key不同payload | 409 `IDEMPOTENCY_KEY_REUSED` |
| same-org/owner已证明后的错误源状态 | 409 `INVALID_STATE_TRANSITION` |
| 新公开名称与当前名称相同（非 exact receipt replay） | 409 `INVALID_STATE_TRANSITION` |
| 将移除最后active admin | 409 `LAST_ACTIVE_ORG_ADMIN` |
| If-Match stale | 412 `PRECONDITION_FAILED`；Organization 更名返回当前 strong ETag |
| recent MFA不满足 | 403 `MFA_STEP_UP_REQUIRED` |
| Resume hold明确BLOCK | 403 `SAFETY_HOLD_BLOCKED` |
| Resume hold不可用/错绑定/过期 | 503 `SAFETY_DECISION_UNAVAILABLE` |
| retained key、receipt/DTO/event/persisted facts损坏或定义storage unavailable | 503 `SERVICE_UNAVAILABLE` |
| COMMIT发送后结果未知 | 503 `COMMAND_OUTCOME_UNKNOWN` |

错误 message 固定，不拼接 target状态、Organization、User、contact、reason note、cookie、Session或数据库异常。高风险跨租户、MFA失败、receipt损坏和replay检测可写独立最小安全审计，但失败审计不能和业务UoW共享一个可能回滚/扩大披露的事务。

## 11. 并发与故障验收矩阵

每个公开命令至少证明：happy path、无关系/跨租户、相邻源状态、同key同payload重放、same key不同payload、stale If-Match（Session为“不适用”）、每个写checkpoint回滚、COMMIT unknown、DTO/event schema和递归secret sentinel。

另有以下专属矩阵：

- Invitation：accept/revoke同一行锁只允许一个终态；非原issuer的当前admin允许，失权issuer拒绝；不调用hold。
- Consent：withdraw与下游使用version竞争；只停止一个purpose；grant/acceptance历史仍在；不调用hold。
- Session：当前/其他Session范围；already-terminal新key不发重复event；旧handle replay撤销exact family current successor；别的family不变。
- Suspend：target为active admin的count=1/2边界；self suspend；hold fake零调用。
- Resume：Organization非ACTIVE、target非SUSPENDED、role全撤销、hold BLOCK/UNAVAILABLE/错ID/version/org/policy/TTL、锁后漂移重评。
- Revoke Membership：ACTIVE/SUSPENDED分支、每个role原子撤销、last admin只按active target计算、REVOKED终态、hold fake零调用。
- Organization public name：NFC/trim/1..160 code point/Cc/Cf 边界；DEMAND_OWNER/跨组织/暂停关系/recent-MFA 等号边界；exact replay 先于同名检查；stale 412 携当前 Organization ETag；与其他五个 ORG_ADMIN 命令的 raw-key 跨 operation 竞争最多一个生效；邀请预览名称立即变更但 Invitation ID/version/ETag/token 不变。

RED必须来自稳定 default-deny sentinel或预期语义差异，`ImportError=0`、fixture error=0；GREEN 前不得放宽断言或以测试后门直改 production store。

## 12. 追踪与交付状态

| REQ | DESIGN | TEST | CODE | 当前状态 |
| --- | --- | --- | --- | --- |
| `REQ-IAM-003`、`REQ-IAM-005` | `DES-AUTHORITY-INVITATION-001`、`DES-AUTHORITY-ATOMIC-001` | `TEST-APP-INVITATION-REVOKE-001` | `identity_access/application/authority_lifecycle.py::RevokeAccessInvitationHandler` | `green · strict Memory UoW` |
| `REQ-CONSENT-002` | `DES-AUTHORITY-CONSENT-001` | `TEST-APP-CONSENT-WITHDRAW-001` | `...::WithdrawConsentGrantHandler` | `green · append-only Memory UoW` |
| `REQ-SESSION-002`、`REQ-IAM-004` | `DES-AUTHORITY-SESSION-001/002` | `TEST-APP-SESSION-LIFECYCLE-001`、`TEST-AUTH-SESSION-REPLAY-001` | `...::RevokeSessionHandler`、`...::RevokeReplayedSessionFamilyHandler` | `green · exact Session/family Memory UoW` |
| `REQ-TENANT-001/002`、`REQ-HOLD-IAM-001` | `DES-AUTHORITY-MEMBERSHIP-001` | 三个 Membership lifecycle TEST | `...::SuspendMembershipHandler/ResumeMembershipHandler/RevokeMembershipHandler` | `green · persisted authority/MFA/hold Memory UoW` |
| `REQ-AUDIT-IAM-001`、`REQ-PRIVACY-IAM-001` | `DES-AUTHORITY-ATOMIC-001`、`DES-AUTHORITY-PRIVACY-001` | 上述全部 TEST | 关闭 event/DTO validators 与 UoW wiring | `green · fault rollback/commit unknown/secret sentinel` |

本页进入 GREEN 后必须补真实 PostgreSQL repository/RLS/并发证据；Memory application GREEN不能替代 migration、数据库角色、FORCE RLS或两个真实连接的证明。

## 13. 首轮语义 RED 证据

2026-08-08 在本文、导航与追踪先落盘后，只新增关闭 command values、窄 storage/schema ports、统一 default-deny application handlers与独立 strict fixtures。执行：

```bash
cd platform
PYTHONPATH=src:tests PYTHONPYCACHEPREFIX=/private/tmp/desire-lifecycle-red-pycache \
  python3 -m unittest discover -s tests/authority_lifecycle -p 'test_*_red.py' -v
```

结果：`Ran 38 tests`、`162 failures`、`0 errors`。3个纯结构测试已经通过：OpenAPI `AccessInvitationAdminDto`/`ConsentGrantDto`/`MembershipAdminDto`直接校验、IAM v1七种lifecycle event直接校验、command repr与fixture/event/DTO递归secret sentinel。其余失败稳定来自`IAM_AUTHORITY_LIFECYCLE_BEHAVIOR_NOT_AVAILABLE`或尚无目标状态/receipt/audit/outbox/hold调用，未出现ImportError、语法、依赖或fixture error。

同轮不包含新RED目录的既有分层回归为 application `100/100`、authentication `22/22`、contract `22/22`、domain `11/11`、authorization `10/10`、PostgreSQL storage（含真实PG18）`56/56`、HTTP/ASGI `18/18`，合计`239/239`全部`OK`。

## 14. Memory application GREEN 证据与剩余边界

2026-08-08 保持上述38项断言、OpenAPI与IAM v1 event schema不变，在正式 application module 中最小实现：版本化keyed receipt identity/payload binding、同事务IN_PROGRESS→COMPLETED、状态/audit/outbox原子写、commit-unknown稳定结果；persisted User/SessionFamily/Session与same-org ORG_ADMIN/recent MFA复核；Invitation/Consent/Session/family replay的单调终结；Membership last-active-admin；以及仅Resume调用的事务外exact SafetyHold和锁后version漂移释放锁再评估。执行：

```bash
cd platform
.venv/bin/python -m unittest discover \
  -s tests/authority_lifecycle -p 'test_*_red.py'
```

结果：退出状态`0`，最终复核`Ran 38 tests in 4.564s`，全部`OK`。逐checkpoint fault均零部分写；`unknown_landed`只返回`COMMAND_OUTCOME_UNKNOWN`而不猜测回滚；same completed receipt零写重放；所有成功DTO和outbox均由关闭schema validator直接验证。执行后对receipt/audit/outbox/DTO递归检查，raw Idempotency-Key、reason note、contact locator与Session handle sentinel均不存在。

同轮既有分层回归为application `100/100`、authentication `22/22`、contract `22/22`、domain `11/11`、authorization `10/10`、PostgreSQL storage（含真实PG18）`56/56`与既有HTTP/ASGI `18/18`，合计`239/239`全部`OK`。文档导航、`py_compile`与`git diff --check`也必须保持通过。

本轮GREEN只证明正式application行为和strict Memory原子UoW；尚未提供这七条lifecycle命令的PostgreSQL repository/UoW、真实行锁顺序、并发receipt claim、operation-specific RLS与真实双连接竞争证据。现有PG18 migration/RLS `56/56`是共享schema基线，不能冒充lifecycle PostgreSQL UoW已实现；该边界继续标为planned。
