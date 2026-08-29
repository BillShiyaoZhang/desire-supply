# IAM 当前政策接受与 Consent 授予命令

> 状态：IAM-01 权威执行设计；OpenAPI authority reference、strict Memory application与[真实 PostgreSQL SELF command repository/UoW](/architecture/iam-policy-consent-postgresql.md)均已GREEN。HTTP presenter/composition 与 E2E 仍未实现，不能由Memory或数据库集成证据替代。
>
> 适用 operation：`acceptCurrentPolicies`、`grantConsent`。邀请接受仍由既有 `AcceptAccessInvitation` 协议拥有，Consent 撤回仍由 [IAM 权限、Consent 与 Session 生命周期](/architecture/iam-authority-lifecycle.md)拥有。

## 1. 为什么必须增加 policy requirement 引用

旧请求只有 `policy_bundle_id` 加 document/offer 选择。在一个 User 同时拥有 creator、多个 Organization Membership 或未来多个角色时，`GET /v1/me` 会返回多个 `policy_requirements[]`。多个 requirement 可能恰好暂时指向同一 bundle；反过来，同一 role 在两个 Organization 中也可能指向不同 current bundle。仅凭 bundle 或 offer 不能回答命令正在满足哪一个持久 authority，也不能决定应锁定哪条 Membership/role grant、哪个 Organization 状态和哪个 stored selector。

以下行为全部禁止：

- 从 User 的 grants 中“任取第一条”、按数据库自然顺序或最新创建时间选 authority；
- 按客户端重复提交的 role、purpose、locale、jurisdiction 推导 selector；
- 把 `policy_bundle_id` 当 selector，或在多个 requirement 中按 bundle 做模糊匹配；
- 用 Session 内角色/Organization 快照代替当前持久 UserRoleGrant/MembershipRoleGrant；
- 让客户端给 `GrantConsent` 自由提交 consent purpose、scope、scope ID、categories、recipient 或 expiry。

IAM-01 因此发布关闭输入 `PolicyRequirementReferenceInput`：

```text
policy_requirement:
  selector_digest: sha256
  scope_type: USER_ROLE | ORGANIZATION_ROLE
  scope_id: null | organization_id
```

关系约束为：`USER_ROLE` 时 `scope_id` 必须为 null；`ORGANIZATION_ROLE` 时必须是 exact Organization ID。引用与 `/me.policy_requirements[]` 的同名三字段逐字相同。它不包含 `role` 或 `purpose`：selector canonical facts 已绑定二者，handler 必须沿 active role grant 与 source Invitation 复算/验证，重复接受客户端声明只会产生可冲突的第二事实源。

在 IAM-01 单一 creator grant、每 Membership 单一未撤销 role grant的不变量下，三元组在一个 User 内唯一。未来允许一个 Membership 多角色时，不改变输入形状：不同 role 对应不同 selector digest。若未来出现无法以该三元组唯一选择的 authority，必须先升级 `/me` DTO、OpenAPI 和持久唯一约束，不能在 handler 中增加排序猜测。

## 2. 关闭 wire 请求

### 2.1 `AcceptPoliciesRequest`

请求恰含：

```text
policy_requirement: PolicyRequirementReferenceInput
policy_bundle_id: OpaqueId
policy_acceptances: 1..20 unique PolicyAcceptanceInput
```

`policy_bundle_id` 必须等于所引用 stored selector 在锁内指向的 exact ACTIVE/effective current bundle。`policy_acceptances` 必须恰好覆盖该 bundle 的 ordered required documents；每项只含 document ID、content SHA-256 和 `affirmed=true`。不能夹带 ConsentOffer choice。

成功返回 exact 更新后的 `PolicyRequirementStatusDto`。响应 ETag 是 User 的新/current强 ETag，因为请求 `If-Match` 的并发 target 是 User。

### 2.2 `GrantConsentRequest`

请求恰含：

```text
policy_requirement: PolicyRequirementReferenceInput
policy_bundle_id: OpaqueId
consent_offer_id: OpaqueId
document_id: OpaqueId
content_sha256: sha256
affirmed: const true
```

这不是自由 scope 输入。`policy_requirement.scope_*` 只选择哪一条 authority/current policy graph；它不是 ConsentGrant 的授权 scope。IAM-01 唯一可执行 offer 为发布在该 exact current bundle 中的：

```text
purpose = PILOT_RESEARCH
scope_type = PLATFORM_PARTICIPATION
scope_derivation = PLATFORM_PARTICIPATION_NULL_SCOPE
scope_id = null
categories = [PROFILE, MATCHING, RESEARCH]
expiry = min(server_granted_at + 365 days, offer.not_after)
```

recipient internal reference、safe recipient label、categories、offer version、purpose、scope、expiry 全部来自受信 immutable `ConsentOffer`，客户端不能覆盖。未来 `ORGANIZATION`、`PROJECT` 或 `RECIPIENT_DISCLOSURE` scope 必须有显式业务入口，服务端从 path/受控资源关系派生 exact scope；不能通过扩展本请求允许任意 `scope_id`。

成功创建或精确复用一个 grant 时返回 `ConsentGrantDto`。响应 ETag 是该 ConsentGrant 的强 ETag，输入 `If-Match` 仍是 User ETag；二者不得混用。

## 3. 共同 actor、Session 与 User 并发

application actor 只携带：`actor_user_id`、`current_session_id`、optional original actor、correlation/causation/trace ID。它不是授权快照。

在 receipt 查询或业务读取前必须预检 active/retained receipt digest key、payload HMAC key，以及 Session row 保存的 handle/CSRF key material。随后从持久事实复核：

1. exact Session 与 family 都为 ACTIVE，Session 是 family current generation；
2. Session、family、User 全部属于 actor；User 为 ACTIVE；
3. `server_now < idle_expires_at` 且 `< absolute_expires_at`，所有时间是 aware UTC；等号已失效；
4. Session 引用成功的 exact AuthTransaction，并具有非空 `auth_time`、`acr`、去重稳定 `amr`；
5. evidence 写入时只复制这些持久 Session/AuthTransaction事实，不接受 request 自报值。

两个命令的 `If-Match` 都锁定 User `aggregate_version`。新 requirement satisfaction 或新 ConsentGrant 各使 User version 恰加一；同一命令无论创建多少 acceptance 也只加一次。精确复用已有 acceptance 或已有相同 ACTIVE grant且没有任何新授权效果时不递增 User。stale User version 在 receipt miss 路径返回 `PRECONDITION_FAILED`，绝不自动覆盖或重试。

`PENDING_ENROLLMENT` User 没有可引用的 active role requirement，必须继续通过 `AcceptAccessInvitation` 完成 onboarding；这两个独立入口不成为绕过 invitation binding 的激活路径。

## 4. exact authority 解析与非披露

handler 以 actor User 和三元组选择且只选择一条当前 authority：

- `USER_ROLE/null`：exact 未撤销 `UserRoleGrant`，其 User、source ACCEPTED Invitation、role、stored selector digest 必须一致；IAM-01 role 只能是 CREATOR；
- `ORGANIZATION_ROLE/{organization_id}`：exact ACTIVE Organization + ACTIVE Membership + 未撤销 `MembershipRoleGrant`，其 User/Organization/Membership/source ACCEPTED Invitation/role/stored selector digest 必须逐字段一致。

不存在、已撤销、inactive、跨 User、跨 Organization或三元组不匹配统一 `RESOURCE_NOT_FOUND`，不透露相邻 authority。repository 返回本不属于 actor/scope 的 row、重复 authority、orphan source、role/selector/reference错绑属于持久不变量损坏，返回 `POLICY_CONFIGURATION_UNAVAILABLE` 或通用 `SERVICE_UNAVAILABLE`，不得过滤后继续。

沿 role grant 保存的 selector digest读取 `PolicySelector`，独立复算 `policy-selector-json-v1` canonical digest并验证 purpose/scope/role与authority一致。selector必须有唯一 current pointer，指向同 selector 的唯一 ACTIVE/effective bundle。缺失、重复、错绑、未来生效、已到 `effective_until`、document/offer/hash损坏均为 `POLICY_CONFIGURATION_UNAVAILABLE`；不能回退到 issued、latest或任一旧 ACTIVE bundle。

客户端 bundle 与一个健康 locked current不同是正常政策升级竞态，返回 `POLICY_BUNDLE_CHANGED` 并提供 safe current bundle ID；它不是服务配置损坏。preflight 后 current pointer改变时，锁内以同一规则裁决，旧 snapshot绝不继续写。

## 5. `AcceptCurrentPolicies` 语义

锁内使用完整 immutable current bundle调用领域 `PolicyBundle.evaluate`，`consent_choices=()`：

- acceptance ID不能重复或未知；集合必须与 required document IDs 恰好相等；
- document ID/hash/legal effect/bundle membership必须逐字段匹配；
- `affirmed` 只能为 true；缺少、额外、false、hash错配均零写；
- required documents按 bundle position形成确定顺序，不能信任请求顺序决定写入或事件顺序。

每个 `(user_id, document_id, content_sha256)` 是 append-only法律 evidence。current bundle 的 document membership/hash/legal effect必须先独立验证；既有 acceptance 的 `bundle_id` 只是它首次产生时的 source audit，不是 evidence identity，也不要求等于本次 current bundle。同一 immutable document被后续bundle合法复用时，只要 owner、document ID/hash、由不可变document得到的legal effect、历史source bundle关系以及完整 Session/AuthTransaction evidence shape一致，就必须复用该 row；复用不改变 accepted_at/source bundle、不写第二条 `PolicyAccepted`。只有真正缺少该三元组时，新 row才记录本次 current bundle。任何历史source、owner、document/hash或evidence错绑才是持久损坏，不能复制或覆盖。

如果 exact requirement 在命令前未满足、命令后满足：

- 为每个真正新增 acceptance写一条 `PolicyAccepted`；
- User version只递增一次；
- 写恰一条 `PolicyRequirementsSatisfied`；
- 返回 `satisfied=true`、current bundle与空 `missing_document_ids` 的 exact requirement DTO。

如果所有 exact evidence 已合法存在且 requirement 已满足，新 idempotency key 可得到无领域变化的成功结果；它仍创建自己的 command receipt和最小 audit，但不更新时间/User，不重复事件。该行为不能把别的 requirement 已满足误当成本 requirement 成功。

## 6. `GrantConsent` 语义

Grant 不要求客户端重新提交全部 policy acceptance。handler 必须从锁内持久 evidence重建 current bundle所需的 exact acceptance集合，并再次以 bundle验证；每个 required current document只要求 actor 已拥有 exact `(document_id,content_sha256)` 的合法不可变 evidence，acceptance首次source bundle可以是旧版本。任一 required document没有该 exact evidence时返回 `POLICY_ACCEPTANCE_REQUIRED`。

随后用请求中的单个 `ConsentOfferChoice` 调用同一领域 bundle评估。choice ID、supporting `CONSENT_TEXT` document ID/hash和 `affirmed=true` 必须精确；offer 必须属于所引用 current bundle、canonical hash可独立复算、`server_now < not_after`。客户端错误 choice返回关闭的 offer/document mismatch；健康 offer在deadline等号时已过期。若已发布 facts 不是第2.2节唯一支持的 generic PILOT_RESEARCH形状，handler以 `POLICY_CONFIGURATION_UNAVAILABLE` fail closed，不把未来 schema enum当成已实现授权。

ACTIVE authority业务键是 `(user_id,purpose,scope_type,scope_id NULLS NOT DISTINCT)`：

1. 先锁 exact完整键；已到期 ACTIVE row以 exact CAS物化 EXPIRED；
2. 仍有效 row仅在 offer/version/bundle、ordered categories、recipient/document/hash，以及按其原 `granted_at` 重算的 `expires_at` 全部相同时精确复用；复用不延长期限、不发第二个事件；
3. 同 authority但任一事实不同返回 `INVALID_STATE_TRANSITION`，不覆盖现有授权；
4. 无有效 row时创建 version 1 ConsentGrant，scope强制为 `PLATFORM_PARTICIPATION/null`，expiry使用本次 server time派生；User version加一并发一个 `ConsentGranted`；
5. WITHDRAWN/EXPIRED历史保留，之后合法新命令可创建新 grant。并发 insert必须由数据库唯一键 + wait/re-read 协议收口为 exact复用或冲突。

## 7. receipt、重放与 commit unknown

两个命令都使用通用关闭 receipt identity：

```text
(USER, actor_user_id, command_name, command_version=1,
 keyed_digest(raw_idempotency_key))
```

raw key只在 command value中以 `repr=False` 暂存。identity digest和payload HMAC使用不同 key domain/ID；新写只用active版本，重放按row保存的 retained key和 `restricted-canonical-json-v1` canonicalizer重算。payload覆盖：

- `POST`、canonical path、target kind=`User`、target ID、User If-Match version；
- command/schema version；
- nested exact requirement reference、exact bundle ID；
- ordered/canonical policy acceptance集合，或 exact offer choice。

相同 key/same payload命中 COMPLETED时，在验证当前受控 Session与principal后重放 receipt保存的 safe body、HTTP status与ETag；不重新验证历史 current pointer、authority、acceptance/offer或旧 If-Match，也不重复领域写/audit/outbox。它不恢复已撤回 grant，不产生 cookie。相同 key/different payload返回 `IDEMPOTENCY_KEY_REUSED`。合法同key并发不发布 `COMMAND_IN_PROGRESS`：数据库唯一claim使竞争者等待首事务commit/rollback，随后只会读取COMPLETED或取得claim；事务外若可见不可能的持久IN_PROGRESS shape视为损坏并返回 `SERVICE_UNAVAILABLE`。unknown key/canonicalizer、损坏binding或safe response同样为 `SERVICE_UNAVAILABLE`。

receipt miss时在同一业务事务先 claim IN_PROGRESS，最终与 User/evidence、最小 AuditEvent、closed outbox和 COMPLETED response一起提交。COMMIT尚未发送且无外调时，仅由adapter按既有 SQLSTATE政策做有界重试；COMMIT发送后的任一异常返回 `COMMAND_OUTCOME_UNKNOWN`，application/server不自动再执行。客户端必须以同 key重试查询 receipt。

## 8. 锁序、current race 与原子边界

READ COMMITTED事务的固定顺序为：

```text
exact receipt identity
→ SessionFamily → Session → User
→ Organization? → Membership? → exact RoleGrant → source Invitation
→ PolicySelector → current PolicyBundle
→ ordered PolicyDocuments → ordered ConsentOffers/categories
→ existing PolicyAcceptances
→ exact Consent active-authority key（Grant only）
→ append evidence/audit/outbox/complete receipt
```

同层多行按 UUID byte order或已发布 position稳定锁定。锁后重新验证 Session/User/version、authority、selector pointer、bundle effective window、acceptance与offer；任何漂移使用本文关闭错误并整体回滚。事务内没有 SafetyHold、OIDC/provider、broker或其他网络调用。两命令不增加 authority role，SafetyHold明确 N/A；消费政策状态的下游业务仍独立执行自己的 hold/authorization gate。

## 9. audit、outbox 与事件范围裁决

AuditEvent只保存关闭枚举/opaque引用：actor/original actor、action、User target、适用 Organization、从持久 authority得到的 role/purpose、auth strength、before/after User version、result=`CREATED|REUSED`、command/correlation/causation/trace。它不保存 request body、policy/consent正文、raw key、selector/hash、Session secret/digest、internal recipient reference、categories副本或自由说明。

outbox继续使用 `iam-v1.schema.json` 的关闭 payload：

- `PolicyAccepted` 是 per-document evidence event，携带 acceptance/User/bundle/document/hash/legal effect，不宣称唯一 authority scope；
- `PolicyRequirementsSatisfied` 是 **User authorization-gate/read-model invalidation event**，不是可单独授权的scope event。现有 payload只有 User与bundle，消费者收到后必须重读 `/me.policy_requirements[]` 或自己的权威投影，禁止因该事件直接授予 Organization/role权限。由于这是明确的粗粒度 invalidation语义，本切片不向已发布 v1 payload追加selector/scope字段；
- `ConsentGranted` 的 `derived_authorization` 已含 exact purpose、派生 scope type、nullable scope ID、ordered categories、supporting document与expiry，足以表达本切片实际授权效果；它不含 internal recipient reference。

同一 command仅为真实新增事实发事件；exact reuse不重复。所有 event在 insert前用完整IAM v1 envelope/payload schema验证，正文、receipt、Session evidence和secret sentinel使整个事务回滚。

## 10. 错误与隐私边界

应用错误顺序固定为：关闭输入已由transport通过 → key/clock preflight → 当前Session/principal → exact receipt → receipt miss后锁User/If-Match → authority/reference → selector/current/bundle → document/offer/evidence → conflict/write/commit。

关键稳定分类：

| 条件 | application错误 |
| --- | --- |
| Session缺失/失效、actor错绑 | `AUTHENTICATION_REQUIRED` 或 deadline明确时 `SESSION_EXPIRED` |
| exact authority不存在/inactive/cross-scope | `RESOURCE_NOT_FOUND` |
| stale User ETag | `PRECONDITION_FAILED` |
| 健康 selector current 与请求 bundle不同 | `POLICY_BUNDLE_CHANGED` |
| selector/pointer/bundle/document/offer/source graph损坏 | `POLICY_CONFIGURATION_UNAVAILABLE` |
| policy required集合/affirmation不完整 | `POLICY_ACCEPTANCE_REQUIRED` |
| document/offer选择错配（领域内部 mismatch 被application收口） | `INVALID_REQUEST` |
| offer deadline达到（领域内部 expired 被application收口） | `INVALID_REQUEST` |
| 同 consent authority已有不同ACTIVE事实 | `INVALID_STATE_TRANSITION` |
| same key/different payload | `IDEMPOTENCY_KEY_REUSED` |
| 定义的storage/key/schema不可用 | `SERVICE_UNAVAILABLE` |
| COMMIT已发送后结果未知 | `COMMAND_OUTCOME_UNKNOWN` |

presentation只映射到现有稳定 HTTP envelope，不回显body、current graph、跨scope资源或异常文本。普通 repr/log/trace/metric禁止出现 raw idempotency key、cookie/CSRF/handle、Session/AuthTransaction evidence、policy body、canonical offer、internal recipient、receipt digest/HMAC或任一测试sentinel。允许 telemetry 仅为 operation、关闭 outcome、replayed布尔、粗粒度new/reused count bucket、latency bucket与trace ID。

## 11. application ports 与实现分期

本切片 production application定义并实现：

- immutable actor/reference/两个 command/result；敏感 key和safe response均不进入 repr；
- narrow clock、ID、keyring、event/safe-response validator；
- operation-scoped store/UoW，只有固定 snapshot/lock/get/values/put/commit方法；
- 明确区分 pre-COMMIT storage unavailable 与 post-COMMIT outcome unknown；
- 两个 Memory handler 的 exact authority/current、Session/User、append-only acceptance、generic ConsentGrant、keyed receipt、audit/outbox与原子fault语义。未知编程异常不在application层伪装成503；只有端口发布的窄 unavailable异常被翻译。

TDD顺序固定为：

1. OpenAPI closed request contract RED→GREEN；
2. strict Memory application semantic RED，覆盖多authority、current race、evidence、reuse、receipt、atomic fault和privacy；
3. 保持业务断言实现 Memory GREEN（已完成）；
4. 按[PostgreSQL SELF UoW 设计](/architecture/iam-policy-consent-postgresql.md)完成fixed repository/UoW +真实锁/唯一/RLS/COMMIT断链 RED→GREEN；
5. HTTP presenter/composition与ASGI E2E；
6. generic PILOT之外的任何 scope另起设计、machine contract与TDD。

Memory GREEN不能证明真实数据库的 `NULLS NOT DISTINCT` 并发、FORCE RLS、receipt claim或socket级commit unknown；已有Invitation Accept adapter也不能被冒充为这两个SELF command的repository。

## 12. 追踪

| ID | 设计保证 | 当前证据 |
| --- | --- | --- |
| `DES-POLICY-CMD-001` | exact requirement三元组选择stored authority，绝不任取grant | OpenAPI/contract + Memory GREEN |
| `DES-POLICY-CMD-002` | User If-Match、current pointer锁内复核、acceptance append-only | Memory GREEN；[PostgreSQL v14真实GREEN](/architecture/iam-policy-consent-postgresql.md) |
| `DES-CONSENT-CMD-001` | Grant绑定exact current bundle，generic null scope只从offer派生 | OpenAPI/contract + Memory GREEN |
| `DES-CONSENT-CMD-002` | active authority唯一、expiry/reuse/withdrawn历史关闭 | Memory GREEN；[PostgreSQL v14真实GREEN](/architecture/iam-policy-consent-postgresql.md) |
| `DES-POLICY-CMD-003` | keyed receipt、Session evidence、atomic audit/outbox、commit unknown与privacy | Memory fault + PostgreSQL v14真实GREEN；E2E planned |

2026-08-08 可执行证据如下：

```bash
cd platform
.venv/bin/python -m unittest -v \
  tests.policy_consent.test_iam_policy_consent_contract \
  tests.contract.test_iam_contracts

PYTHONPATH=src:tests .venv/bin/python -m unittest -v \
  tests.policy_consent.test_iam_policy_consent_commands_red
```

contract-first最初3项得到`1 failure + 2 errors`，精确暴露旧机器契约缺少reference/schema扩展；补齐并加入事件范围护栏后，新contract `4/4`、既有contract `22/22`，合计`26/26 OK`。application为有效语义RED：`Ran 11 tests in 2.719s`、`86 failures`、`0 errors`。失败覆盖exact多authority success、session/authority非披露、User If-Match/current race、document/offer矩阵、跨bundleimmutable acceptance复用、active grant expiry/conflict、retained receipt key/restart、13个写checkpoint、commit unknown和秘密隔离；default-deny/immutable/schema样例等结构护栏已通过。

排除上述11项刻意RED后，原稳定集合在当时migration head上仍为`307/307 OK`：非storage`239/239`、真实PostgreSQL 18 storage`68/68`；新增contract `4/4`另行保持GREEN。这段记录保留为TDD RED历史，不代表当前状态。

随后只实现application/窄helper并保留全部业务矩阵；唯一测试阶段转换是把不可能与成功语义并存的default-deny scaffold哨兵改成合法入口护栏。另修正两处fixture真实性而不放宽业务结果：既有ConsentGrant保持数据库约束`auth_time <= granted_at`；current race作为外部已提交变更保留在store中，同时断言被测事务`0 put/0 checkpoint`且receipt/audit/outbox零新增。最终证据为：

```text
policy/consent application   11/11 OK
new + existing contracts     26/26 OK
py_compile                   OK
```

Memory GREEN证明exact多authority、generic null-scope、Session/User/current、跨bundleacceptance reuse、active grant reuse/expiry/conflict、retained-key receipt/restart、13个写checkpoint、pre/post-COMMIT fault及secret-free response/audit/outbox/telemetry。它仍不证明真实PostgreSQL的receipt claim/`NULLS NOT DISTINCT`并发、FORCE RLS、socket ack-loss，亦不证明正式HTTP presenter/server或E2E。
