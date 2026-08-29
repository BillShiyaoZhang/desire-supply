# ADR-0004：IAM onboarding、持久化与 PostgreSQL 执行协议

> 状态：已接受
>
> 日期：2026-08-07
>
> 决策驱动：IAM-01 的实现准备复核发现 onboarding 身份绑定、邀请角色、consent 派生、命令收据、Session family 与 RLS/事务仍有多个可导致权限旁路或不可实现契约的选择。

## 背景

[身份、租户、政策同意与会话设计](/architecture/identity-tenancy-consent.md)已经固定纵切面边界，但仅凭抽象状态仍不能唯一回答：

- OIDC callback 后如何证明 accept actor 仍是 invitation recipient；
- invitation token 在 callback 后清除时，accept 从哪里获得授权；
- 一个组织邀请能否携带多个角色，role child 如何保证 parent scope 和非空；
- invitation 发出后政策升级时，selector、issued bundle、current bundle 与 `/me` requirement 分别以什么为事实源；
- 客户端提交的 consent categories、recipient 和 supporting document 是否可信；
- 命令收据的唯一键、canonical hash、commit-unknown 和 capability 重建如何实现；
- Session rotation 如何保证一个 family 只有一个 active successor，CSRF token 如何重建；
- 匿名/global invitation、`/me` 自读、组织管理员和 SYSTEM 如何通过 FORCE RLS；
- PostgreSQL 版本、隔离级别、安全重试和 migration runner 如何固定。

这些不是实现细节；不同选择会改变安全边界、API schema、数据库约束和 TDD 验收，因此由本 ADR 收口。

## 决策

### OIDC onboarding 使用服务端一次性绑定

Invitation capability 的 wire field 统一为 `access_invitation_token`，只在 `InspectAccessInvitation` 和 `BeginOidcAuthorization` 提交；不得另设含糊的 `access_token`、`token` 或 `join_url` 字段。`BeginOidcAuthorization` 的 Session cookie 可选，服务端按以下关闭矩阵推导 purpose，客户端不能提交或覆盖 purpose/expected User/invitation/contact ID：

| ACTIVE Session | `access_invitation_token` | 服务端结果 |
| --- | --- | --- |
| 无 | 无 | LOGIN；未知主体不能因此创建 User |
| 有 | 无 | LOGIN 再认证；绑定 current User并轮换，callback 不允许换账号 |
| 无 | 有效 | ENROLLMENT；绑定 exact invitation/version/contact，callback 后即使解析为既有 User也保持此 exact onboarding binding |
| 有 | 有效 | STEP_UP；同时绑定 current/expected User 与 exact invitation/version/contact |

无效/过期 Session 按匿名处理，但 token 仍独立验证，冲突 body 不能降级 purpose。`BeginOidcAuthorization` 验证 token 后，在 AuthTransaction 中保存 invitation_id、invitation_version、预期 recipient_contact_id 及该 row 的不可变 binding tuple；callback 后浏览器清除 token，`AcceptAccessInvitation` 不再接收 raw token。OpenAPI 必须把 `access_invitation_token`、token-bearing URL 与返回的 `authorization_url` 标记 `x-sensitive: true`、`x-log-policy: redact`，入口日志/trace/错误不得记录其值。

AuthTransaction 状态固定为：

```text
PENDING → EXCHANGING → SUCCEEDED
                    ↘ RESULT_UNKNOWN
PENDING/EXCHANGING → FAILED
```

它还保存：purpose=`LOGIN | ENROLLMENT | STEP_UP`、initiating browser binding digest、initiating_session_id/user_id（适用时）、expected_user_id（step-up 必需）、invitation_id/version/contact ID与冻结 tuple（enrollment/step-up 必需）、state/nonce/PKCE secret、deadline、attempt/version 和 provider error class。callback 以 compare-and-swap 把 PENDING 变 EXCHANGING；并发 callback 不能执行第二次 exchange。provider 明确拒绝进入 FAILED；已接收 code 但结果不确定进入 RESULT_UNKNOWN，不自动重放 code；成功原子进入 SUCCEEDED 并建立/轮换 Session。

这些“secret”不是一列未定义JSON。首版必须分别持久化：state keyed digest/key ID、临时`__Host-ds_oidc` browser cookie keyed digest/key ID、nonce digest及加密ciphertext/key ID、PKCE verifier ciphertext/key ID、公开S256 challenge/method，以及exact provider issuer/audience、固定callback redirect URI、登记过的same-origin return_to和`iam-security-v1` policy version。raw state/browser secret/nonce/verifier/code/authorization URL/provider token不落库。临时cookie至少256 bit，`Secure; HttpOnly; SameSite=Lax; Path=/`、省略Domain、Max-Age=600；callback缺失或错cookie时即使state正确也失败。nonce/verifier只有在全部保存key material预检成功后才能解密并交给provider adapter。

callback 的 compare-and-consume 采用两个本地事务夹一个外调：第一事务CAS `PENDING/v1→EXCHANGING/v2`并写唯一exchange owner、attempt=1、claimed_at后先COMMIT；确认commit的owner才在事务外调用一次provider exchange；第二事务锁回同一owner/attempt，原子写`SUCCEEDED | FAILED | RESULT_UNKNOWN` v3及成功时的contact/User/ExternalIdentity/Session。claim COMMIT unknown时绝不调用provider；最终COMMIT unknown不重做exchange也不重建raw Session secret。claim成功后进程丢失或code发送后的响应不确定只能收口RESULT_UNKNOWN。并发/重复callback看到EXCHANGING或任一终态不能第二次exchange。provider/JWKS无副作用preflight可在claim前失败并让transaction保持PENDING，除此之外不存在EXCHANGING回退PENDING的隐式状态。

Recipient locator 和 provider verified claim 使用同一版本化 RecipientBindingPort 规范化并 HMAC。`iam.contact_points` 是 recipient binding 的唯一事实源：不可变 binding tuple 为 `(type, binding_digest, digest_key_id)`，发布后不得原地修改；locator ciphertext 可在终态和保留期后清除，但 tuple 保留。该 tuple 只有非唯一受限 lookup index，明确不得全局 UNIQUE，也不得成为自动账号合并依据。AccessInvitation 只保存 `recipient_contact_id` 外键，不复制 digest 或 key ID。

provider成功值还必须显式包含`issuer`、`subject_digest`及其key ID、上述recipient tuple、aware UTC `auth_time/iat/exp`、acr与非空amr。adapter在返回前完成签名、exact HTTPS issuer allowlist、audience/client ID、多audience时exact azp、nonce、redirect、PKCE、code single-use以及`iat <= now < exp`/适用nbf的版本化skew校验；application永远看不到raw subject或token。ExternalIdentity只按exact `(issuer, subject_digest, subject_digest_key_id)`解析且仍受`(issuer,subject_digest)`唯一防线约束；首切片不跨digest key猜测合并。

每一次 invitation accept——包括既有 User——都必须先创建绑定该 exact Invitation 的 `ENROLLMENT` 或 `STEP_UP` AuthTransaction。transaction 保存 `expected_contact_point_id`，并把 begin 时该不可变 row 的 `(type,binding_digest,digest_key_id)` 冻结为 protocol evidence；callback 按该 ID 加载 exact contact row，先拒绝本不应发生的 tuple 漂移，再以恒定时间比较 provider verified claim 的 tuple，不能用 digest 查找后任取一行。该快照不替代 `contact_points` canonical source，也不得用于 locator lookup 或账号合并。成功后轮换出的 Session 同时保存 `verified_contact_point_id` 与 `verified_for_invitation_id`。普通 `LOGIN` Session、只碰巧具有相同 digest 的另一 contact row、为另一 Invitation 完成的 Session 都不能接受当前 Invitation。Accept 只比较以下 exact ID 条件并要求全部成立：

```text
session.verified_contact_point_id = invitation.recipient_contact_id
session.verified_for_invitation_id = invitation.id
session.auth_transaction.invitation_id = invitation.id
session.auth_transaction.invitation_version = If-Match version
```

Session onboarding binding 是一次性的。Accept 成功在同一事务轮换 Session，successor 清除 `verified_for_invitation_id` 和 onboarding transaction reference；失败不提升权限。SUSPENDED/CLOSED User 即使 provider 认证成功也不得建立可用于业务的 Session：SUSPENDED 返回统一受限结果并只允许恢复/隐私流程的后续专门设计，CLOSED 永远拒绝；首切片不创建这两类 Session。

LOGIN未知subject不创建User。只有仍有效的ENROLLMENT且exact contact tuple通过时才可在最终事务创建`PENDING_ENROLLMENT` User与唯一ACTIVE ExternalIdentity；contact row未绑定时原子绑定到resolved User并标记VERIFIED，已绑定另一User则拒绝。既有identity解析到的User可走匿名ENROLLMENT或expected User相等的STEP_UP，但同locator/同digest另一contact row绝不能代替exact row。并发ExternalIdentity唯一冲突只能重读同一exact identity并重新执行上述矩阵，不能创建第二User或按contact自动合并。

匿名LOGIN/ENROLLMENT成功创建新SessionFamily generation1；当前ACTIVE Session发起的LOGIN/STEP_UP在最终事务重新锁定并复核initiating family/session current后于同family轮换generation+1。新Session的`auth_time/acr/amr`来自本次provider结果，created/last_activity/updated为server now，idle/absolute deadline分别为now+30分钟/12小时且exclusive。持久secret事实关闭为32-byte handle的digest/key ID、独立32-byte CSRF salt、CSRF key ID/digest；raw handle/CSRF只在最终COMMIT确认后进入敏感响应。LOGIN的verified invitation/contact字段为空，ENROLLMENT/STEP_UP逐字保存transaction冻结的invitation/contact/verified_at/auth_transaction ID。

### 每个 AccessInvitation 恰好一个 target role

IAM-01 不支持多角色邀请。AccessInvitation 直接保存 `target_scope` 与 `target_role`，删除 invitation role child table：

- `CREATOR_ENROLLMENT` 必须是 `target_scope=USER`、`target_role=CREATOR`、organization_id 为空、is_initial_admin=false；
- `ORGANIZATION_MEMBERSHIP` 必须是 `target_scope=ORGANIZATION`、target_role 为 `ORG_ADMIN | DEMAND_OWNER`、organization_id 非空；
- `is_initial_admin=true` 时 target_role 必须恰为 ORG_ADMIN，issuer 为 SYSTEM；
- 同一 invitation 的 purpose/scope/role/organization/contact 创建后不可修改。

Membership 建立后增加第二个组织角色需要未来显式 `GrantMembershipRole` 命令、独立 MFA/授权/审计设计，不能通过第二个邀请绕过 `(organization_id,user_id)` 唯一关系。

### Invitation issuer、initial-admin 与 prospective hold target

`IssueAccessInvitation` 的 issuer 只能来自两条关闭路径，客户端 command 不携带 purpose、issuer、Session 认证强度或 `is_initial_admin`：

- USER 路径只允许已认证 ACTIVE User 为其 **同一** ACTIVE Organization 发出普通 `ORGANIZATION_MEMBERSHIP` 邀请。middleware 给出的 actor ID 只是定位键；应用必须加载 exact `session_id`，要求 Session 与 family 都 ACTIVE/current、两个 exclusive deadline 未到、Session user 与 actor 相等，并以该 Session 持久化的 `auth_time/acr/amr` 判定 10 分钟 exclusive recent MFA。随后在同一写事务锁 Organization、该 User 的 Membership 和未撤销 ORG_ADMIN grant，逐项复核 ACTIVE、同组织、角色和版本；不得信任 request/context 自报的 MFA、Membership 或 role snapshot；
- SYSTEM 路径要求受认证、按 operation allowlist 的受控 workload credential。它只可发 `CREATOR_ENROLLMENT/USER/CREATOR`，或为 PENDING_ADMIN Organization 发 `ORGANIZATION_MEMBERSHIP/ORGANIZATION/ORG_ADMIN` 的初始管理员邀请。后者由服务端推导 `is_initial_admin=true`；SYSTEM 不可借此为 ACTIVE Organization 发普通成员邀请，USER 永远不能发 creator 或 initial-admin invitation。PENDING_ADMIN 同时最多一个 ISSUED initial-admin；替换必须先使 exact 旧邀请进入终态，或由 Bootstrap/reissue 编排在同一事务 CAS 旧邀请后再创建新邀请，不能把第二个开放邀请解释为“重发”。

receipt preflight 确认不存在已完成结果后，handler 在任何 SafetyHold 调用前从受控 ID source 预分配最终 `invitation_id`；prospective aggregate version 固定为 `1`，之后任何 retry 都复用这个 ID。Issue 的 rich hold request 固定 `action=IssueAccessInvitation`、`target_type=AccessInvitation`、`target_id=该预分配 ID`、`target_version=1`、权威 organization ID（creator 为 NULL）和部署的 safety policy version。provider 在事务外调用；BLOCK/UNAVAILABLE、时间窗或任一回传绑定错误均按既有 403/503 语义 fail closed。锁后若该 ID 已存在，或 Session/family、Organization、Membership/role、creator platform policy、locale fallback policy、selector version/current pointer 任一与 hold 前计划不同，旧 ALLOW 立即失效：回滚、释放锁、重新读取并在事务外重新 evaluate，绝不把一份 ALLOW 复用到另一 Invitation ID 或另一 authority snapshot。

### Invitation 固化 selector，Accept 解析同 selector 的 current bundle

Policy selector 是独立持久事实。首版 `policy-selector-json-v1` 只包含 `{access_purpose, scope_type, target_role, jurisdiction, locale}`，以 NFC、固定字段顺序、无浮点 canonical UTF-8 后的 SHA-256 作为 `selector_digest`；canonicalization version、facts 与 digest 发布后不可修改，同一 facts 不能映射多个 digest。它不包含 effective window；时间窗属于同 selector 下的 bundle 版本。

`IssueAccessInvitation` 不接受客户端 selector、locale 或 jurisdiction。selector facts 的来源关闭如下：

- purpose、scope type 与 target role 来自合法 Invitation shape：creator 为 `CREATOR_ENROLLMENT/USER_ROLE/CREATOR`，组织邀请为 `ORGANIZATION_MEMBERSHIP/ORGANIZATION_ROLE/{ORG_ADMIN|DEMAND_OWNER}`；
- 组织邀请的 jurisdiction 来自 issue 事务中锁定的 exact Organization；creator invitation 使用版本化 platform creator-enrollment policy 的默认 jurisdiction；
- creator locale 使用同一版本化 platform policy 的默认 locale；组织 locale 由服务端版本化 locale fallback policy 按 exact organization jurisdiction/purpose/role 解析一次；首切片没有 User preferred-locale selector fact；
- `Accept-Language`、UI locale、recipient locator、inviter 对 locale/jurisdiction 的自报值、进程区域设置和 presentation 不得参与或覆盖这些 facts；合法 `target_role` 仍按上一项成为关闭 fact。未来引入 preferred locale 必须先新增权威持久事实与迁移/重新签发设计。

Issue 在锁定 Organization（适用时）与 exact selector 后，要求 `PolicySelector.current_bundle_id` 指向同 selector 且满足 `status=ACTIVE`、`effective_at <= server_now`、`effective_until IS NULL OR server_now < effective_until` 的 bundle；然后把 `policy_selector_digest` 与该时刻的 `issued_policy_bundle_id` 同时保存到 Invitation。二者与 purpose/scope/role/organization/contact 一样创建后不可变，issued bundle 只表示发出时的政策证据，不是永久接受条件。selector/pointer/bundle 不一致或没有 current 时，issue 返回 503 `POLICY_CONFIGURATION_UNAVAILABLE` fail closed。

Accept 只沿 Invitation 保存的 digest 锁定 selector并验证 current pointer、同 selector、ACTIVE 状态和 exclusive effective window，不从当前 Organization、角色、请求语言或 DTO 重算，也不按 `created_at`/semantic version 猜测：

- 请求的 `policy_bundle_id` 若仍是 issued/其他旧 bundle而不是 current，返回 409 `POLICY_BUNDLE_CHANGED` 和 current 的公开 ID；Invitation 保持 ISSUED，所有领域事实零写；
- 请求提交 current 时继续验证 current documents/ConsentOffer，即使 current 已不同于 issued；不得额外要求 `current_bundle_id = issued_policy_bundle_id`；
- current 缺失、错 selector、非 ACTIVE、未来生效、`server_now >= effective_until` 或多候选冲突一律返回 503 `POLICY_CONFIGURATION_UNAVAILABLE` fail closed，不回退 issued 或“最新”bundle；
- current required document 的已有 exact PolicyAcceptance 可以复用，缺失文档仍须补齐。

Accept 创建的 `UserRoleGrant` 或 `MembershipRoleGrant` 必须保存与 source Invitation 相同的 immutable `policy_selector_digest`。`/me.policy_requirements[]` 对每条 ACTIVE grant 分别读取该列、沿 exact selector current pointer解析 required bundle，再结合 append-only acceptances计算 satisfied/missing documents；scope ID 来自 grant 的 User/Membership 关系。application/repository 返回已解析结果，presentation 只能映射，禁止从 role、Organization、locale、jurisdiction 或请求上下文重新选择 facts、计算 digest或把多个 grant 合并为一个 bundle。

### ConsentGrant 只从不可变 ConsentOffer 派生

客户端不能提交或扩大 purpose、scope、data categories、recipient 或 expiry policy。PolicyBundle 暴露不可变 ConsentOffer；safe DTO 必须包含经发布审核的 `recipient_label`、关闭的 expiry rule、必需 hard `not_after` 与 `canonical_offer_sha256`，但不暴露内部 recipient ref。canonical hash 覆盖 offer ID/version、bundle、purpose、scope derivation、categories、内部 recipient ref、公开 label、document/hash、expiry rule/not_after 与 optional 等全部服务端派生事实。客户端只提交 `consent_offer_id`、该 offer 所引用的 `document_id`、`content_sha256` 和 `affirmed=true`。服务端要求文档 ID/hash 与 offer 和当前 bundle 精确一致，并从 offer 派生 scope、全部 ConsentGrant 字段与到期日。客户端不能提交 scope ID、categories、recipient 或自选 expiry。

初始 `PILOT_RESEARCH` offer 固定为：

- purpose：`PILOT_RESEARCH`；
- scope_type：`PLATFORM_PARTICIPATION`，不接受客户端 scope_id；
- data_categories：`PROFILE | MATCHING | RESEARCH`；
- recipient/controller：版本化平台研究控制者 opaque reference；
- recipient_label：经法律审核的稳定公开控制者名称；
- supporting document：当前 bundle 内精确的 `CONSENT_TEXT` document ID/hash；
- expiry：关闭规则为 server granted_at 起 365 天，pilot end 作为 hard `not_after`，取更早时间；
- optional：true，不得预选或混入 required PolicyAcceptance。

未来 recipient-specific disclosure 由后续切片先创建不可变、绑定准确 recipient/scope 的 ConsentOffer，再复用同一 Grant 命令。

### Signed release canonicalization、信任与原子发布

`PublishPolicyBundle` 的签名内容固定为机器契约已有的关闭 `iam-policy-release-v1` manifest。canonicalizer 必须先按 schema 拒绝未知/缺失字段、浮点、naive/非 UTC 时间、重复 ID/枚举外值和非 NFC 字符串；它不能“修复后再验签”。对象按 RFC 8785 JCS key 顺序、array 保持 manifest 声明顺序、时间使用唯一 UTC `Z` 表示、正文按已验证为 canonical 的原 UTF-8 bytes（不做 trim、换行或 Unicode 静默改写）编码。manifest 恰覆盖：schema version、bundle ID、selector canonicalization/facts/digest、exact predecessor、effective window、按 position 的完整 documents、required document IDs，以及按 position 的完整 ConsentOffers。`manifest_sha256` 是这些 canonical bytes 的 unkeyed SHA-256；签名输入是该 32-byte digest，而不是调用方提交但未复算的字符串。

每个 offer 同时使用 `consent-offer-json-v1` 独立计算 `canonical_offer_sha256`。canonical object 覆盖并只覆盖：canonicalization version、offer ID/version、bundle ID、purpose、scope type/derivation、按 position 的无重复 data categories、内部 `recipient_ref`、公开 `recipient_label`、supporting document ID/content SHA-256、expiry rule、expiry days、hard `not_after` 与 optional。release manifest 必须包含这些完整事实和该 hash；publisher 从事实独立复算并恒定语义比较，不能信任 artifact 自报 hash，也不能只签 offer ID 列表。supporting document 必须是同 bundle、exact hash、`legal_effect=CONSENT_TEXT` 的 document。任一 offer 字段、顺序、hash 或 document binding 改变都会改变 manifest digest并使旧签名失效。

签名 envelope 的 `signature_algorithm` 与 `signature_key_id` 不进入 manifest，却不是自由提示：verifier 先由 key ID 取得不可变 trust record，要求该 ID 永久绑定一个算法、公钥、用途 `IAM_POLICY_RELEASE`、允许的 manifest schema/jurisdiction/purpose、有效窗和状态，再要求 envelope algorithm 精确相等。production 首版只接受批准的 Ed25519 key；测试 HMAC 只可在 synthetic/test mode 的显式 trust record 中出现。未知算法/key、错用途、未生效、过期或撤销 key 均为 `POLICY_RELEASE_INVALID`；trust/key/approval provider 明确不可用则为 503 `SERVICE_UNAVAILABLE`，不能 fallback 到另一 key/算法。

调用 publisher 与签名者是两条独立授权链。`PolicyPublisherContext` 只能由认证层从受控 workload credential构造，要求 SYSTEM identity的版本化allowlist明确包含 `POLICY_PUBLISH`，并把 command ID、exact selector digest与bundle ID传给无BYPASSRLS的`iam_system` scope；artifact/body中的system ID或original actor不能构造/覆盖它。应用在进入UoW前复核credential purpose、有效窗和状态，数据库再以exact GUC/RLS限制statement；一个合法release签名不能把任意普通SYSTEM任务变成publisher。

每次新的 publish 还必须取得不可变 legal approval credential，按 `(manifest_sha256, signature_key_id)` 精确查询并验证 `decision=APPROVED`、审批有效窗/撤销状态以及 credential 中的 manifest digest 与 key ID逐 byte 相等。credential ID、审批主体和 manifest digest进入最小 AuditEvent 安全字段，审批正文不复制；该 credential 与 trust record依法至少保留到 release 历史不再需要解释。不存在、拒绝、过期、撤销或绑定错误按 `POLICY_RELEASE_INVALID` 零写；依赖不可用按 `SERVICE_UNAVAILABLE`。已完成 receipt 的 exact replay只重放既有结果，不因审批或 key 后续轮换而改写历史。

签名成立后仍必须执行领域 validator；合法 signer 不能绕过以下规则：selector purpose/scope/role shape合法，NFC facts 独立复算为 exact digest；document ID/version唯一、正文 hash正确、locale/jurisdiction 与 selector compatible、kind/legal-effect合法，至少一个 required document且 required集合恰为 documents子集；offer满足上一段全部约束；新 bundle/offer ID未被占用，既有 document只可按 exact全部不可变事实复用。首版发布只允许 `effective_until=NULL` 与 aware UTC `effective_at <= transaction_timestamp()`；replacement 还要求 `effective_at > predecessor.effective_at`，并把 predecessor 的 exclusive `effective_until` 精确关闭为该值。future release 保持 DRAFT，到时重新调用同一命令。

publish 锁定/创建 exact selector 后按以下关闭矩阵推进 current：selector 不存在或 `current_bundle_id=NULL` 时 manifest predecessor 必须为 NULL；已有 current 时 manifest predecessor 必须逐字等于 pointer，pointer row 必须是同 selector、ACTIVE、开放 window 的唯一 current。调用方 stale predecessor 或并发 CAS 冲突返回 `PRECONDITION_FAILED`；数据库已有 pointer/row/digest错配或多个 ACTIVE candidate 返回 `POLICY_CONFIGURATION_UNAVAILABLE`，均零部分写。事务只可按“旧 current → SUPERSEDED并关闭窗口；新 bundle/documents/offers → ACTIVE；selector pointer/version → 新 bundle”推进，并由 partial unique/trigger作最后防线；migration、fixture 与 seed没有例外。

### 命令收据与 canonical payload

业务命令收据唯一键固定为：

```text
(principal_kind, principal_id, command_name, command_version, idempotency_key_digest)
```

target kind/id、HTTP method/path、If-Match 和请求 payload 属于被哈希内容，不进入唯一键。原始 Idempotency-Key 不落库，只保存版本化 keyed digest。payload 使用 `restricted-canonical-json-v1`：先通过关闭 schema并显式填充协议缺省，字符串按 NFC 规范化，整数保持十进制且首版拒绝浮点，再按 RFC 8785 JCS 排序；加入 method、规范 path、target、If-Match、command/schema version；排除 Cookie、CSRF、trace；联系人、token 等 A 层输入先替换为各自 keyed digest。最终 `payload_hash=HMAC-SHA-256(receipt_key, canonical_bytes)`。

内部 `PublishPolicyBundle` **不是**该协议的例外。它以受认证 SYSTEM 为 principal；非秘密 UUID `command_id` 仍可作为 receipt PK、causation ID，并以独立 idempotency-key HMAC domain 对 `JCS-UTF8({"command_id": command_id})` 计算五元 identity中的 digest。其 transport profile 固定为 `http_method=INTERNAL`、`canonical_path=/internal/iam/policy-bundles/publish`、`target_kind=PolicyBundle`、target ID为 manifest bundle ID、If-Match 为 NULL。关闭 payload body 包含由本地 canonicalizer **复算**的 manifest SHA-256和 exact signature algorithm/key ID/signature bytes；不能用 artifact 自报 manifest hash或公开 unkeyed SHA-256直接充当 `payload_hash`。它与外部命令使用同一 retained idempotency/payload keys、canonicalization version、IN_PROGRESS→COMPLETED claim、commit-unknown 和 rotation规则。

receipt 与业务状态在同一事务中从事务内的 IN_PROGRESS 写成持久化 COMPLETED；回滚不留下 receipt。并发相同唯一键等待首事务：commit 后相同 hash 重放安全响应，不同 hash 返回 409；回滚后第二请求可正常执行。应用一旦向 PostgreSQL 发送 `COMMIT`，之后发生的超时、断链或驱动异常一律映射 `COMMAND_OUTCOME_UNKNOWN`，不得猜测失败或在同一请求内重执行。客户端只用同 key 重试：存在 COMPLETED receipt 则重放；不存在才在业务唯一约束保护下重新执行。

IssueAccessInvitation receipt 不保存 capability token。新执行使用独立 invitation-token key policy 的 active key，并持久化 32-byte nonce、exact `token_key_id`、expiry 和 ID；token codec 必须显式接收保存的 key ID，按版本化 `access-invitation-token-v1` 对 `(format_version, invitation_id, token_nonce, token_key_id, expires_at)` 的唯一 canonical bytes做认证，输出完全确定的相同 token/link。key ID/format version必须在 token的受认证部分，不能只作为未认证 routing hint。验证/重建 key与旧 token-format implementation保留到 Invitation、receipt 和法定重放窗全部结束；缺旧 key/format时返回 `SERVICE_UNAVAILABLE`，绝不能用当前 key、随机 nonce或新格式“恢复”。

Issue 的 COMPLETED receipt只保存 contract-valid safe response、response schema version，以及关闭的无秘密 metadata `{kind, version, invitation_id, invitation_version, token_format_version, token_key_id}`；首版 `invitation_version=1`。它不保存 nonce、token、link、recipient/contact/binding digest、Session/MFA证据或原始 idempotency key。重放在输出 token前必须同时证明：receipt principal/command/version/key digest/payload HMAC与当前认证 actor和请求精确相等；target kind/ID、metadata invitation ID/version、safe response invitation ID/aggregate version互相一致；exact Invitation的 ID及不可变 issuer kind（USER时还包括issuer user）、organization/role/expiry/contact、token key和nonce shape与原命令/receipt一致。Invitation之后可因合法终态转换递增当前version，但不能改变上述creation facts；重建旧token也绝不复活其状态。contact row的 immutable binding tuple还必须与本次输入经独立 recipient-binding key domain得到的 tuple一致。USER replay仍要求当前 exact ACTIVE Session、recent MFA，以及同组织ACTIVE Membership/未撤销ORG_ADMIN grant；SYSTEM replay仍要求同一受控 operation credential。任一错配、缺 row、多候选、未知 schema/key/format均以 `SERVICE_UNAVAILABLE` fail closed并记录不含秘密的安全审计，不向另一 principal/Invitation重建 capability。

### Session family、rotation 与 CSRF

新增 `iam.session_families`：id、user_id、status、current_generation、aggregate_version、revoked_at/reason。`iam.sessions` 保存 family_id、generation、predecessor_session_id、handle_digest、verified_contact_point_id/verified_at、verified_for_invitation_id、auth_transaction_id、auth context、deadlines、status 和 rotation_reason。

数据库约束：

- `UNIQUE(family_id,generation)`；
- `UNIQUE(predecessor_session_id)`，非空 predecessor 只能有一个 successor；
- partial unique：每个 family 最多一个 `status=ACTIVE` Session；
- rotation 锁 session_family，递增 generation，在同一事务撤销 predecessor 并创建 successor；
- login、step-up、AccessInvitation accept 和账号恢复都走同一 rotation command；
- 已撤销 predecessor handle 的重放锁 family 并撤销该 family，不能创建新的 successor。

CSRF token 以请求 cookie 中的 raw Session handle、数据库保存的随机 `csrf_salt`、`session_id`、generation 和版本化 `csrf_key_id` 作为 HMAC 输入确定性派生。数据库不保存 raw Session handle 或 raw CSRF token，但保存 `csrf_digest` 用于恒定时间校验；`GET /auth/session` 读取当前 cookie 后可重建同一 masked synchronizer token并核对 digest。每次 rotation 使用新的 handle、salt 和 key generation，使 predecessor 的 token 立即失效。

Accept 与 Session rotation 同事务提交后若响应或 `Set-Cookie` 丢失，浏览器只剩已撤销 predecessor。系统不为旧 handle 设置宽限，也不把 successor raw handle/CSRF token 写进 receipt：旧 cookie 重放仍立即撤销该 family并返回统一 Session 失效，用户必须重新完成普通 OIDC LOGIN。随后同一 User 的新 ACTIVE Session 用相同 command key/request 重试时，handler 在验证认证主体、规范 payload hash 后、检查 Invitation/onboarding guard 之前读取 COMPLETED receipt；principal 与 hash 精确匹配即可重放安全 JSON body。这个窄例外只适用于已完成 receipt，不再次改变领域状态或轮换 Session；cookie/CSRF 从来不是 receipt 响应的一部分。不存在 receipt 时仍必须满足 exact Invitation binding 才能执行命令。

### PostgreSQL 18、事务、RLS 与迁移

IAM-01 固定 PostgreSQL 18 当前 security minor，开发、CI 与生产保持同一 major 并持续升级 security minor；Python 驱动固定 psycopg 3。普通短 IAM 写事务使用 READ COMMITTED，以文档化的 `SELECT ... FOR UPDATE` 锁序、唯一/检查/外键约束和 CAS 保证不变量；确有跨行谓词需要时必须在命令设计中显式升级隔离级别并新增并发测试，不能全局暗改。

只有在 `COMMIT` 尚未发送、事务没有 provider/网络外调且没有开始外部副作用时，SQLSTATE `40001`、`40P01` 或 `55P03` 才允许在同一 command/idempotency context 内最多重试 3 次，并使用有上限 jitter。发送 `COMMIT` 后的任何异常均为 `COMMAND_OUTCOME_UNKNOWN`，绝不由 server 自动重试；provider exchange 也不进入数据库事务重试循环。

在线 `iam_app` 与内部 `iam_system` 都不是 table owner、没有 BYPASSRLS。FORCE RLS 的关闭 scope 为 `SELF | ORGANIZATION | INVITATION | AUTH_PROTOCOL | PUBLIC_POLICY_READ | POLICY_PUBLISH | SYSTEM`，按操作分策略：

- self policy：`app.actor_user_id` 可读取自己的 User、Membership、Policy/Consent 和 Session；普通 SELF 不得直接 SELECT Organization；
- `/me` self-summary exception：跨本人多个 Organization 的安全摘要只经 hardened `SECURITY DEFINER iam_api.read_me_self_summary()`。它不接受 actor/organization 参数，要求固定 repository 从已认证 Session 设置 transaction-local session/actor，先加载 exact ACTIVE Session 并要求 session.user_id 与 actor 相等，再以该派生 User join 本人 Membership。函数使用固定 `search_path=pg_catalog,iam,pg_temp` 与全限定静态 SQL、无 dynamic SQL，只返回 User/Membership/Organization `organization_id/public_name/type/status/aggregate_version` allowlist，由 presentation 层从版本生成 ETag；函数 owner 为不可登录窄角色，无 BYPASSRLS/表所有权，撤销 PUBLIC EXECUTE，仅授予 `iam_app`。应用仍无 Organization 直接 SELECT；缺失/不匹配 context、跨主体、伪造 scope/search_path 和直接 SQL 必须有负测试；
- receipt replay policy：只允许已认证 principal 通过 exact command/version/key digest 固定 statement 读取自己的一条 COMPLETED receipt；不能 list、按 target 查找或读取其他 principal；
- organization-admin policy：显式 app.organization_id + ACTIVE Membership/ORG_ADMIN，只作用于同组织行；
- auth-protocol/onboarding policy：专用 `iam_onboarding` 数据库角色，只能在 `app.operation` 为枚举的 INSPECT/BEGIN/COMPLETE/ACCEPT，且 row invitation_id 与 AuthTransaction/Session 的 exact invitation scope 相等时访问 global 或组织 Invitation；ACCEPT 还要求 Session 的 `verified_for_invitation_id` 和 `verified_contact_point_id` 分别精确匹配 invitation/contact ID；匿名组织 preview 只返回 `OrganizationInvitationPreviewDto.public_name`；
- public-policy-read policy：要求 exact `app.policy_bundle_id`，只能读取该 ID 的 ACTIVE、已生效、不可变 PolicyBundle/Document 与 safe ConsentOffer projection；禁止 list selector、DRAFT/未来 bundle、evidence 或其他 bundle；
- policy-publish policy：只允许 `iam_system` 在 exact `app.policy_selector_digest + app.policy_bundle_id + command_id` scope 创建/锁定/激活/替代，绝无 global publish/read scope；
- SYSTEM policy：专用 `iam_system` 角色，要求枚举 operation、command_id 和显式 target user/organization/invitation scope，不提供无条件跨租户 SELECT；
- schema_owner 仅 migration/恢复使用，不作为在线连接。

应用只能通过固定 repository/SQL statement 设置这些 transaction-local context；客户端值不能直接成为 GUC。除上述唯一 self-summary 函数外 IAM-01 不提供 SECURITY DEFINER 入口；后续例外必须另作设计，且同样固定 search_path、关闭动态 SQL、只返回字段 allowlist、撤销 PUBLIC EXECUTE并单独契约测试。

迁移由仓库内建、带版本/checksum 的有序 SQL runner 执行：全局 advisory lock、单 migration 事务、expand/migrate/contract、schema history、owner/RLS/constraint 精确校验。runner 使用 schema_owner 凭据且不接收任意外部 SQL；在线应用启动时只校验期望版本，绝不自动迁移。回滚应用不能假设数据库 down migration。

## 其他同步决策

- ConsentWithdrawal 的并发 target 是 ConsentGrant，因此使用 ConsentGrant If-Match；GrantConsent/AcceptPolicies 仍使用 User If-Match。
- `/me` 的 `policy_requirements` 必须是按 selector/purpose/显式 role/scope 分项的数组，多角色/多组织主体不能被压成一个 bundle；selector digest 来自对应 ACTIVE `UserRoleGrant`/`MembershipRoleGrant` 保存的 source-invitation selector 列，application 沿该 digest 解析 ACTIVE/effective current，DTO/presentation 不按 role/Organization/locale/jurisdiction 临时重算。Organization summary、Membership/Invitation/Consent DTO 必须提供各自强 ETag 来源；AccessInvitationAdminDto 还必须同时返回沿 Invitation 存储 selector 解析的当前 required policy bundle、aggregate_version 与同版本 ETag，不能返回仅供审计的 issued bundle冒充 current。新增 `GET /v1/me/consents` 返回安全列表和逐项 ConsentGrant 强 ETag，使重新登录后仍能重新取得 withdraw 的 If-Match。匿名 invitation 只嵌入仅含 `public_name` 的 `OrganizationInvitationPreviewDto`，Invitation 自身携带 aggregate_version/entity_tag，不复用宽 `OrganizationSummaryDto`。
- Policy bundle 初次发布和升级都只通过内部 `PublishPolicyBundle` 生产命令，而不是 migration、seed SQL 或测试专用 fixture：它锁定 exact selector+bundle、校验 signed release manifest/内容 hash/effective_at，在同一事务激活新 bundle、替代旧 bundle并写 receipt/audit/outbox。migration 只安装结构；部署初始 artifact、fixture 与 E2E 调用同一应用命令。真实启用还要求法律审批。
- 只有 invitation issue/accept 与 Membership resume 作为 authority increase 调用版本化 `SafetyHoldDecisionPort`。不可变 `SafetyHoldDecisionResult` 必须回带 exact action/target type/ID/aggregate version/organization/policy version、evaluated_at 与 exclusive valid_until；严格 fake 可注入 ALLOW/BLOCK/UNAVAILABLE、错绑定、过期与定义的 `SafetyHoldUnavailableError`。BLOCK 映射 403 `SAFETY_HOLD_BLOCKED`；UNAVAILABLE、错绑定、deadline 等号/过期和定义的 provider unavailable 映射 503 `SAFETY_DECISION_UNAVAILABLE`。锁后 target version 改变时旧 ALLOW 失效，只能退出事务后重新 evaluate。Membership suspend/revoke、Invitation revoke、consent withdraw、logout/revoke Session 是安全降权，不得被任一 hold 结果阻断；`/me`、政策读取/接受与 consent grant 也明确 N/A。原有同组织、MFA、状态和 last-admin 守卫仍适用；紧急主体/Session 撤销不能依赖 Membership 管理入口。
- 启动配置硬守卫禁止 production/real-data mode 启用 fake issuer，禁止 fake 与 real provider 隐式 fallback；不满足时进程在监听端口前失败。

## 被否决的方案

- callback 后继续让浏览器保存并再次提交 invitation token：跨完整重定向易丢失且扩大 bearer 暴露面；不采用。
- 一个 invitation 携带多个角色：使 Membership 唯一性与后续增权语义混杂；IAM-01 不采用。
- 客户端提交 consent categories/recipient/document：可扩大授权；不采用。
- 只用一张无状态 Session 表或“实现时选 family row/rotation counter”：无法证明单一 successor；不采用。
- 不锁行、只靠 READ COMMITTED 应用前置检查：容易产生 last-admin、policy selector 和 rotation write skew；不采用。首版采用 READ COMMITTED + 固定行锁序 + 数据库约束。
- 给 onboarding/SYSTEM `BYPASSRLS`：会把窄协议例外变成通用跨租户入口；不采用。
- ORM 自动迁移或应用启动自动跑 SQL：不可审计、难恢复；不采用。

## 后果与验证义务

- OpenAPI 的 AcceptAccessInvitation request 不含 token；inspect/begin/issue 的 capability 字段统一为 `access_invitation_token` 并标记敏感/日志 redact；OIDC begin 使用 optional Cookie 矩阵；Organization invitation request 改为单一 target_role；consent request 改为 ConsentOffer 选择，safe offer DTO 提供 recipient label、expiry/not_after 与 canonical hash；`GET /me/consents` 提供逐项 ETag。
- 事件 payload 只包含派生后的 purpose/scope/category/document 引用，不包含联系人、token 或 provider claim。
- 数据库需要 AuthTransaction 状态、canonical contact FK、session_families、partial unique、hardened self-summary、exact PUBLIC_POLICY_READ/POLICY_PUBLISH scope、operation-specific RLS 和 migration runner 集成测试。
- 新增 `TEST-DB-IAM-RECEIPT-001`、`TEST-AUTH-TRANSACTION-001`、`TEST-AUTH-ONBOARDING-001`、`TEST-AUTH-ACCEPT-RECOVERY-001`、`TEST-DB-SESSION-001`、`TEST-DB-RLS-IAM-001`、`TEST-DB-MIG-IAM-002`、`TEST-CONFIG-IAM-001`、`TEST-APP-POLICY-001`、`TEST-APP-POLICY-SELECTOR-002` 与 `TEST-APP-HOLD-IAM-001`，先 red 再实现。`TEST-APP-POLICY-SELECTOR-002` 当前为下一轮 planned application TDD，必须覆盖 issue selector/issued 固化、旧 bundle 409/current bundle继续、status/effective window fail-closed、grant digest 传播和 `/me` presentation 不重算。

完整表、命令、API 与追踪以 [身份、租户、政策同意与会话设计](/architecture/identity-tenancy-consent.md)同步后的内容为准。
