# Demand、不可变版本与审核/资金/匹配边界

> 状态：首个交易侧纵向切片的权威详细设计；独立机器契约、domain与Memory application已GREEN，尚未进入PostgreSQL、RLS、HTTP或production composition。
> 适用范围：Organization 拥有的 Demand、不可变 DemandVersion、提交与运营审核、资金资格镜像、发起 Matching 的边界，以及各接收者读取投影。
> 前置依赖：[目标平台领域模型与状态协议](/architecture/platform-domain-model.md)、[组织租户根与角色作用域](/decisions/0002-tenant-root-and-role-scopes.md)、[Creator Profile 设计](/architecture/creator-profile.md)与[跨平台 Outbox](/architecture/outbox-delivery.md)。

## 1. 用户结果、范围与事实所有权

本切片让 ACTIVE Organization 中的 ACTIVE `DEMAND_OWNER` 完成以下闭环：

1. 为本 Organization 创建一个私有 Demand 和首个不可变草稿版本；
2. 追加新版本、提交审核，并安全接收结构化的补充要求；
3. 由被明确分配、无利益冲突的 `OPERATIONS_REVIEWER` 验证 exact 版本；
4. 通过 Payments Context 的已保障资金事实推进到 `FUNDED`；
5. 冻结 DemandVersion、Funding 和规则要求并发起 Matching；
6. 在无选择、取消、到期或最终选择时保持可审计的终态历史。

Demand Context 拥有 `Demand`、`DemandVersion`、`DemandSubmission`、`DemandReviewAssignment`、`DemandReview`、资金资格的最小镜像和 `MatchingRequest`。它不拥有 User、Organization、Membership、角色、真实 Funding、MatchRun、Invitation、Selection、Project 或支付供应商对象。

真实资金状态只由 Payments Context 拥有；Demand 只接受经过 durable inbox/process manager 验证、且精确绑定 DemandVersion 的 `FundingSecured/Failed/Cancelled/Replaced` 事实。Matching Context 只接受 `MatchingRequested` 后创建 attempt；它不能直接把 Demand 改为 `MATCHING`。唯一允许跨 Context 同事务的 `CompleteSelection` 仍以[目标平台领域模型 §7.1](/architecture/platform-domain-model.md#71-允许的本地原子事务)为准。

旧 MVP demand JSON 是研究资料而不是组织授权或平台 Demand。导入最多生成隔离的待核对草稿和 `legacy_source_ref`；不能根据 `client_org_id`、`status=funded`、`funding_evidence_ref` 或联系人自动建立 Organization、Membership、审核或 Funding 事实。

## 2. 聚合、版本和追加事实

### 2.1 Demand 根

`Demand` 至少保存：

| 字段 | 规则 |
| --- | --- |
| `id` | 事务前预分配的不可推测 Opaque ID；进入 receipt payload 与 hold 绑定 |
| `organization_id` | 不可变租户根；所有子记录以包含该列的复合外键关联 |
| `created_by_user_id` | 创建时 actor，只作证据；不替代当前授权 |
| `status` | `DRAFT / SUBMITTED / NEEDS_CHANGES / VERIFIED / FUNDING_PENDING / FUNDED / MATCHING / MATCHED / NO_MATCH / CANCELLED / EXPIRED` |
| `aggregate_version` | 从 1 开始；每个成功外部或 process-manager 命令恰增加 1 |
| `current_version_id` | 始终指向本 Demand 的一个不可变 DemandVersion |
| `verified_version_id` | 仅 `VERIFIED` 之后可非空，必须等于 exact current；进入修订时清空 |
| `current_funding_id` | 仅保存 Payments 的 opaque ID；不是资金事实来源 |
| `current_matching_request_id` | `MATCHING` 时绑定唯一开放请求；不是 MatchingAttempt 的替代品 |
| `client_reference_digest/key_id` | 同 Organization namespace 唯一；raw client reference 不落库、不回显 |
| `cancelled/expired_at`、`reason_code` | 只在相应终态出现；reason 为关闭代码，不存自由正文 |
| `created_at/updated_at` | 数据库 UTC aware time；只随根事实变化 |

`MATCHED/CANCELLED/EXPIRED` 为终态。`NO_MATCH` 不是终态：它可以在资金仍可验证的前提下再次匹配，也可以进入 `NEEDS_CHANGES` 形成新版本。任何版本变化都会使旧 Funding/Matching 资格失效；不得把旧 marker 改绑到新版本。

### 2.2 DemandVersion

每次保存都是 append-only 新行；没有 PATCH 或原地 JSON 更新：

| 字段 | 规则 |
| --- | --- |
| `id/demand_id` | 版本自身 ID 与父 Demand ID；必须属于同一 Organization/Demand |
| `version_no` | Demand 内从 1 单调递增且唯一；失败事务不消耗可观察编号 |
| `based_on_demand_version_id` | 可空；非首版必须指向本 Demand 的更小 version_no |
| `content` | 关闭 `demand-content-json-v1` 对象；自插入起不可变 |
| `content_sha256` | JCS UTF-8 规范字节 SHA-256；保存、提交、读取、审核和 Matching capture 都独立复算 |
| `demand_schema_version` | 首版固定 `1` |
| `canonicalization_version` | 固定 `demand-content-json-v1` |
| `taxonomy_bundle_id` | 发布时必须仍为受信、有效 bundle；不从当前配置重算历史 |
| `created_by_user_id/created_at` | 服务端事实；客户端不能自报 |

根只允许一个 `current_version_id`，但旧版本永不覆盖。提交、补件和验证使用独立追加事实，不给 DemandVersion 增加可漂移的“审核状态”：

- `DemandSubmission`：`demand_id/version_id/submission_no/submitted_by/submitted_at/content_sha256`；同一 version 最多一个有效提交；
- `DemandReviewAssignment`：assignment、reviewer User、平台职责 grant、有效期、冲突检查版本与状态；
- `DemandReview`：绑定 exact submission/version/assignment，结果只为 `NEEDS_CHANGES | VERIFIED`；包含关闭 reason codes、required field codes、budget-health code、risk code与最小证据摘要；自由评语进入受限 case note，不进入普通 Demand 表、DTO、事件或日志；
- `DemandFundingMarker`：绑定 exact Funding ID、DemandVersion ID、amount/currency digest、provider/manual verification reference digest、source event ID 与 observed status；仅作已验证跨 Context 事实；
- `MatchingRequest`：绑定 exact DemandVersion、Funding、taxonomy/budget/matching/reason-code复合版本和 request status；每个 Demand 同时最多一个 OPEN。

## 3. 关闭 Demand 内容

目标平台不直接复用 MVP payload。状态、Organization、actor、consent version、funding commitment/evidence、ID 和时间均不属于客户端可写内容。首版 `content` 仅包含以下关闭分组：

| 分组 | 首版业务事实 | 主要接收者 |
| --- | --- | --- |
| `problem` | 背景、domain code、problem-type codes、目标用户类别、期望结果 | owner、assigned reviewer、matcher；邀请卡仅安全摘要 |
| `scope` | 带受控 item ID 的 deliverables、明确 out-of-scope | owner、reviewer、matcher；邀请后按快照披露 |
| `acceptance` | 带 criterion ID 的验收标准、响应天数、owner role code | owner、reviewer、matcher；邀请后披露必要项 |
| `skills` | must-have/nice-to-have taxonomy skill 与最低等级 code | owner、reviewer、matcher、邀请卡 |
| `matching` | problem/domain/task受控 codes | owner、reviewer、matcher、邀请卡 |
| `schedule` | start/due、estimated days、weekly hours、duration weeks | owner、reviewer、matcher、邀请卡 |
| `budget` | min/max/direct cost 的最小货币单位整数和 ISO-4217 currency | owner、reviewer、funding；候选只见预算兼容或获准报价范围 |
| `milestone_plan` | item ID、短 label、percent；只是资金/协议前计划 | owner、reviewer、funding；不等于 Project Milestone |
| `risk` | uncertainty/urgency/dependency codes、data sensitivity、data handling plan | owner、reviewer、matcher；候选只见工作所需安全规则 |
| `ai` | allowed/required、data-model policy、human-review code | owner、reviewer、matcher、邀请卡必要规则 |
| `collaboration` | BCP-47 languages、work mode、feedback cadence、team preference | owner、reviewer、matcher、邀请卡 |
| `location` |需求 region 与允许 creator region codes | owner、reviewer、matcher、邀请卡 |
| `declarations` | decision authority、data rights、procurement intent 三个显式确认 | owner、reviewer；不进入邀请卡 |

结构与规范化至少满足：

- 所有对象关闭；未知字段、enum、taxonomy code、重复 item ID/skill、非 NFC 字符串、控制字符和不合法日期拒绝；
- 所有金额与百分比为整数并拒绝 bool、float、NaN/Infinity；`minimum <= maximum`、`direct_cost >= 0`、milestone percent 恰合计 100；
- `start_date <= due_date`；`estimated_days 1..366`、`weekly_hours 1..80`、`duration_weeks 1..104`、`response_days 1..30`；
- `ai.required=true` 要求 `ai.allowed=true`；`high/restricted` 数据必须有非空 data handling plan，允许 AI 时还必须有 data-model policy；
- must-have 至少一项且不得与 nice-to-have 重复；matching domains 必须包含 problem domain；
- 文本字段有按 schema 固定的 code-point/UTF-8 byte 上限；序列化、错误、审计和 telemetry 不能回显原文；
- 联系方式、身份材料、访问 token、支付凭据、普通 URL、文件正文和供应商 payload 没有可表示字段；受控证据只以独立 Context opaque ID 关联；
- 草稿可以缺少“提交完整性”要求的业务项，但已出现的分组仍须结构合法。提交额外要求：至少一个 deliverable/criterion/must-have skill、有效 schedule/budget/milestone plan、三项 declarations 全为 true，并通过版本化 taxonomy、budget-health、risk 和 data-plan policy；
- `content_sha256` 的签名面包含 Demand ID、version_no、schema/canonicalization/taxonomy bundle 和全部内容；不含可变状态、review、funding、receipt 或 Session 事实。

自由业务文本可能含敏感内容，不能仅因 JSON schema 合法就向更多接收者披露。Submit 前由版本化的 content-policy port 做数据分类与禁止内容检查；port 不保存正文，结果绑定 `content_sha256/policy_version`。provider unavailable 为 503 且零业务写。草稿 owner 读取不把该检查结果宣称为内容安全认证。

### 3.1 `demand-content-v1` 精确机器边界

首版机器契约固定为独立的 `contracts/domain/demand-content-v1.schema.json`。schema root 是内容哈希的完整签名面，而不是可直接作为 HTTP body 的数据库对象：

```text
{
  demand_schema_version: 1,
  canonicalization_version: "demand-content-json-v1",
  demand_id, version_no, taxonomy_bundle_id,
  content
}
```

其中 `content` 只允许本节列出的十三个分组；草稿允许分组缺失，但已出现的分组必须完整、关闭且类型正确。Submit完整性由domain policy在schema结构合法之后检查，不能通过另一个宽松“draft schema”或在JSON中加入`is_draft`实现。v1字段名和关闭值固定如下：

| 分组 | 关闭字段 |
| --- | --- |
| `problem` | `background`、单一`domain_code`、唯一`problem_type_codes`、唯一`target_user_category_codes`、`desired_outcomes` |
| `scope` | `deliverables[{item_id,description}]`、`out_of_scope`；item ID匹配`^[a-z][a-z0-9_-]{0,63}$`且分组内唯一 |
| `acceptance` | `criteria[{criterion_id,description}]`、`response_days`、`owner_role_code=DEMAND_OWNER` |
| `skills` | `must_have/nice_to_have[{skill_code,minimum_level_code}]`；level只为`FOUNDATION/WORKING/ADVANCED/EXPERT` |
| `matching` | 唯一`problem_codes/domain_codes/task_codes` |
| `schedule` | ISO日期`start_date/due_date`、整数`estimated_days/weekly_hours/duration_weeks` |
| `budget` | 非bool整数`minimum_amount_minor/maximum_amount_minor/direct_cost_amount_minor`、三位大写`currency` |
| `milestone_plan` | `items[{item_id,label,percent}]`；percent为1..100非bool整数且完整计划合计100 |
| `risk` | `uncertainty_code/urgency_code`为`LOW/MEDIUM/HIGH`、唯一`dependency_codes`、`data_sensitivity`为`PUBLIC/INTERNAL/HIGH/RESTRICTED`、可空`data_handling_plan` |
| `ai` | bool `allowed/required`、可空`data_model_policy`、`human_review_code=NEVER/RISK_BASED/ALWAYS` |
| `collaboration` | 唯一BCP-47 `languages`、`work_mode=REMOTE/HYBRID/ONSITE/FLEXIBLE`、`feedback_cadence=ASYNC/DAILY/TWICE_WEEKLY/WEEKLY`、`team_preference=SOLO/PAIR/SMALL_TEAM/ANY` |
| `location` | `demand_region_code`与唯一`allowed_creator_region_codes`，均为受控region code而非地址 |
| `declarations` | bool `decision_authority/data_rights/procurement_intent`；Submit时三者必须逐项为true |

taxonomy code统一为2..64个ASCII大写字母、数字、`_.:-`，region code为2..32个ASCII字母、数字和`-`。业务文本必须NFC、不得含Unicode C0/C1控制字符；`background/data_handling_plan`分别至多4000/2000 code points与12000/6000 UTF-8 bytes，description/outcome至多500 code points与1500 bytes，milestone label至多120 code points与360 bytes。JSON Schema负责关闭对象、形状、code-point上限和基础类型；domain validator继续负责UTF-8 byte上限、NFC、唯一业务键、跨字段关系、合法日历日期、日期顺序、金额顺序、percent合计、skill集合不相交、matching domain包含problem domain以及AI/data policy联动。

JCS输入按RFC 8785的对象键顺序与UTF-8编码构造；禁止float，因此首版无需定义非整数number的JCS边界。hash函数必须把上述root完整编码后计算SHA-256；同一语义对象的输入成员顺序不影响hash，任何Demand ID、version_no、taxonomy bundle或内容变化都必须改变hash。

## 4. 状态命令与守卫

以下细化 [目标平台领域模型 §8](/architecture/platform-domain-model.md#8-demand-状态)，并保持其状态集合：

| 转换 | 命令 | 权威 actor | 附加守卫 |
| --- | --- | --- | --- |
| 无 → DRAFT | `CreateDemand` | exact Organization `DEMAND_OWNER` | ACTIVE User/Session/Family、Organization/Membership/role/policy；Organization 内 client reference digest 唯一；同事务插入 version 1 |
| DRAFT/NEEDS_CHANGES → 原状态 | `CreateDemandVersion` | exact owner-org `DEMAND_OWNER` | expected Demand version；full replacement content合法；base必须为current；清除旧 verified/funding/matching资格 |
| DRAFT/NEEDS_CHANGES → SUBMITTED | `SubmitDemand` | exact owner-org `DEMAND_OWNER` | current完整、content policy通过、当前taxonomy/budget/risk政策未漂移；创建exact submission |
| SUBMITTED → NEEDS_CHANGES | `RequestDemandChanges` | assigned `OPERATIONS_REVIEWER` | assignment ACTIVE/未过期/无冲突；reason codes与required fields非空；不受 SafetyHold 阻止 |
| SUBMITTED → VERIFIED | `VerifyDemand` | assigned `OPERATIONS_REVIEWER` | same exact submission/hash；身份/付款主体/决策权/预算健康/风险均通过；reviewer不是创建者且不属于 owning Organization |
| VERIFIED → FUNDING_PENDING | `RequestInitialFunding` | scoped `FINANCE_OPERATOR` 或 SYSTEM workflow | exact verified version；生成不可变 funding requirement ID；无 active requirement |
| VERIFIED/FUNDING_PENDING → FUNDED | `ApplyFundingSecured` | authenticated SYSTEM consumer | durable inbox exact event；Funding target/amount/currency/version一致且 status SECURED；manual模式的双人核实在 Payments 内完成 |
| FUNDING_PENDING → VERIFIED | `ApplyFundingRetryExhausted` | authenticated SYSTEM consumer | source Funding terminal且没有 active replacement；source event去重 |
| FUNDED/NO_MATCH → MATCHING | `RequestMatching` | assigned reviewer 或 authenticated SYSTEM workflow | exact current verified version/Funding仍SECURED；规则包冻结；无 OPEN matching request/attempt；hold允许 |
| MATCHING → NO_MATCH | `ApplyMatchingAttemptClosed` | authenticated SYSTEM consumer | exact request/attempt为关闭终态；source event去重 |
| NO_MATCH → NEEDS_CHANGES | `ReopenDemandForRevision` | exact owner-org `DEMAND_OWNER` | 无开放 attempt；记录资金再验证计划 code；清除 verified/funding pointer，不修改 Payments |
| MATCHING → MATCHED | `CompleteSelection` 内部步骤 | authenticated SYSTEM + original DEMAND_OWNER | 按唯一跨 Context 原子协议校验 Selection/Invitation/attempt并创建 Project shell |
| DRAFT..MATCHING → CANCELLED | `CancelDemand` | exact owner或assigned reviewer | 未有 Project；关闭 reason；有资金时只发退款要求，不伪造退款完成；安全降权不受 hold 阻止 |
| DRAFT..FUNDED → EXPIRED | `ExpireDemand` | authenticated scheduler | `expires_at <= database_now`，无开放 invitation/project；定时 command identity 去重 |

Create/CreateVersion/Submit/Verify/RequestFunding/RequestMatching 都不能被客户端直接写 status。`Apply*` 命令不公开为普通 HTTP，必须验证 workload attestation、consumer inbox、事件 envelope/schema/source aggregate version与 exact target；原始 broker payload不得进入领域命令。

### 4.1 v1 关闭命令输入

为避免HTTP、application command与receipt hash各自发明输入，首版外部body固定如下：

- `CreateDemand`只接受`client_reference/taxonomy_bundle_id/content`；raw client reference仅进入域分离keyed digest，生产实体、事件、响应、receipt和repr均不保存或回显；
- `CreateDemandVersion`只接受`based_on_demand_version_id/taxonomy_bundle_id/content`，base必须等于锁内current；
- `SubmitDemand`、`RequestInitialFunding`和`RequestMatching`使用关闭空对象；exact current version/hash、金额/币种、规则和资金事实均由服务端读取并冻结；
- `RequestDemandChanges`只接受非空唯一`reason_codes/required_field_codes`；不接受自由review note；
- `VerifyDemand`只接受四个必须为true的`identity_subject_verified/payment_subject_verified/decision_authority_verified/budget_health_verified`及关闭`budget_health_code/risk_code`；
- `CancelDemand`只接受关闭`reason_code`；`ExpireDemand`及全部`Apply*`命令没有公共HTTP body。

路径中的organization/demand/assignment、`If-Match`和Idempotency-Key属于receipt payload但不得复制进body。客户端自报actor/session/role/status/version/hash/time、Funding/Matching状态或provider evidence一律由OpenAPI关闭对象拒绝。

## 5. IAM、职责分离与 SafetyHold

普通 owner 命令的权威投影最初记为 `iam_api.authorize_demand_owner_v1`；PostgreSQL online UoW已将其替代为唯一事务锁定入口 `iam_api.lock_demand_owner_authority_v1`，旧非锁定名称不并行授权。该投影至少绑定：

```text
session_user + app.actor_id + app.session_id + app.organization_id
+ app.operation + exact demand_id(optional for create)
```

其结果只允许 ACTIVE User/Session/Family、ACTIVE Organization/Membership、未撤销 `DEMAND_OWNER` MembershipRoleGrant 与该 grant 固化的当前 policy requirement。Demand 在线角色没有 IAM 表 SELECT；函数固定 search_path、静态 SQL、PUBLIC 无 EXECUTE、精确 online role allowlist且不接受请求自报角色。

运营与财务权限不是 Organization role：

- review 命令要求 `DemandReviewAssignment` 与 IAM `OPERATIONS_REVIEWER` duty 同时有效；assignment绑定 Demand、reviewer、purpose、有效期和 conflict attestation；
- 同一 User 不能创建并验证 Demand，owning Organization 的成员不能验证本组织 Demand；assignment issuer不能是被分配 reviewer本人；
- `FINANCE_OPERATOR` 只能创建/复核 funding requirement，不能验证 Demand；人工资金双确认由 Payments Context 保证两个不同人员，审核 reviewer 不能单独满足；
- SYSTEM 使用 operation-scoped workload credential，每次只处理一个 exact organization/demand/source event；没有全租户默认旁路。

`SubmitDemand`、`VerifyDemand` 与 `RequestMatching` 增加内容或候选可见性，必须在事务外执行版本化 SafetyHold。hold绑定 actor、organization、demand ID、prospective aggregate version、exact DemandVersion/content hash与 action；权威、assignment、root/version/hash或 policy version在锁内漂移时回滚并在事务外以新事实重评。BLOCK 映射 403，provider unavailable 映射 503，均零业务写。Create/SaveDraft/RequestChanges/Cancel/Reopen/Expire/资金失败重置属于私有写或安全降权，不被 hold 阻止。

未知 demand、跨组织、非 owner、无 assignment或失效 duty 对普通请求统一 404。只有已证明 exact关系后才区分 stale ETag 412、状态冲突 409与内容不完整 422。

## 6. 幂等、并发与原子性

所有外部写带 `Idempotency-Key`；除 Create 外带 Demand 强 ETag `If-Match: "vN"`。create 的 raw `client_reference` 只参与 keyed digest，不持久化。receipt identity为：

```text
(principal_kind, principal_id, organization_id,
 command_name, command_version,
 idempotency_key_digest_key_id, keyed_idempotency_digest)
```

payload HMAC覆盖 method、canonical path、target/organization、If-Match、command schema、raw client reference 的域分离 keyed digest及关闭 body。receipt保存canonicalization/key IDs、payload hash、target/version、safe closed response与状态；raw key/reference、content、Session/CSRF secret、review note和provider evidence不得落入 receipt/repr。

先验证当前 ACTIVE Session/主体，再查 COMPLETED receipt；同主体的新 ACTIVE Session可重放，异主体和失效Session不可。same key/same hash返回原 safe response且不再次调用 hold/content policy；same key/different hash为409且零写。持久 IN_PROGRESS 不暴露内部状态，等待合法竞争或返回503；不能增加未发布 wire code。

业务事务固定锁序：IAM Family → Session → User → Organization → Membership → MembershipRoleGrant/policy marker → platform duty/review assignment（如适用）→ Demand root → current DemandVersion → current Submission/Review → Funding marker → MatchingRequest → source inbox/receipt claim。按 ID 集合的行使用规范 byte 序；不存在行不得在后面逆序补锁。事务内再次核对所有事务外检查。

聚合、append-only facts、receipt、audit和outbox一次 COMMIT。每个逻辑写具有稳定checkpoint；任一点失败全部回滚。COMMIT_SENT断链必须discard物理连接，用新连接读取 exact receipt + Demand/version/fact集合：完整 COMPLETED且hash/response/target/version一致才安全重放；明确不存在才可有限重试；IN_PROGRESS/corrupt/部分事实均503并报警，不猜测成功。

## 7. API 与关闭错误集合

首版外部/受控操作面：

```text
POST /v1/organizations/{organization_id}/demands
GET  /v1/organizations/{organization_id}/demands/{demand_id}
POST /v1/organizations/{organization_id}/demands/{demand_id}/versions
POST /v1/organizations/{organization_id}/demands/{demand_id}/submit
POST /v1/organizations/{organization_id}/demands/{demand_id}/cancel

GET  /v1/operations/demand-review-assignments/{assignment_id}/demand
POST /v1/operations/demand-review-assignments/{assignment_id}/request-changes
POST /v1/operations/demand-review-assignments/{assignment_id}/verify
POST /v1/operations/demands/{demand_id}/request-funding
POST /v1/operations/demands/{demand_id}/request-matching
```

Process-manager命令没有公共 route。owner路径必须显式 organization ID；session 不保存 active tenant。所有响应对象关闭，写响应 `Cache-Control: no-store`、trace ID和新 ETag；请求 body 不接受 actor/user/role/session/org/status/version/hash/server time/funding status。

首版 wire code 固定为：

| HTTP | 允许 code |
| --- | --- |
| 400 | `INVALID_REQUEST` |
| 401 | `AUTHENTICATION_REQUIRED`, `SESSION_EXPIRED` |
| 403 | `ACCESS_DENIED`, `SAFETY_HOLD_BLOCKED` |
| 404 | `RESOURCE_NOT_FOUND` |
| 409 | `DEMAND_ALREADY_EXISTS`, `INVALID_STATE_TRANSITION`, `IDEMPOTENCY_KEY_REUSED`, `TAXONOMY_BUNDLE_CHANGED`, `FUNDING_FACT_CHANGED`, `MATCHING_RULE_BUNDLE_CHANGED` |
| 412 | `PRECONDITION_FAILED` |
| 422 | `DEMAND_VALIDATION_FAILED`, `POLICY_ACCEPTANCE_REQUIRED`, `REVIEW_CONFLICT`, `FUNDING_REQUIRED` |
| 503 | `POLICY_CONFIGURATION_UNAVAILABLE`, `SERVICE_UNAVAILABLE` |

repository、数据库、content-policy、hold和consumer错误只能收口为上述 code；不能把 SQLSTATE、provider reason、assignment存在性或 content classifier详情泄露到 message/trace。

## 8. 读取与字段披露

Demand 没有 public/anonymous query。四种投影分别固定查询与allowlist：

| 投影 | 调用者 | 内容 |
| --- | --- | --- |
| `OWNER_ORG` | exact ACTIVE organization relation | full current content、版本/状态、结构化 review要求、funding/matching安全状态；不含 reviewer身份、内部证据或provider ref |
| `REVIEW_ASSIGNMENT` | exact ACTIVE assigned reviewer | full submitted content、submission/hash、受控 budget/risk证据摘要；不含联系人、支付对象、其他reviewer note |
| `MATCH_INPUT` | exact MatchingRequest workload | exact verified immutable content/hash/taxonomy/funding资格、硬过滤所需私密预算/风险；不得被需求方或候选调用 |
| `OPPORTUNITY_SNAPSHOT_SOURCE` | exact eligible MatchCandidate/Invitation builder | 只返回获准摘要、deliverables/criteria、schedule、skills、协作/数据/AI规则与预算兼容输出输入；不返回预算底数、direct cost、内部risk/review/funding证据 |

Opportunity/Invitation生成时保存接收者相关不可变披露快照；后续 Demand 修订不扩张旧快照。列表与分页使用固定keyset cursor，cursor HMAC覆盖 operation、actor/organization/filters/sort/last tuple/schema/key IDs；offset和任意sort/filter不进入v1。

强 ETag来自接收者可见 projection hash + aggregate version；v1未知 `If-None-Match` 仍按全局 HTTP closed-header规则拒绝，不能临时实现半套304。owner/reviewer响应默认 no-store；内部投影不进入共享cache。

## 9. 事件、审计与隐私

关闭事件至少包括：

- `DemandCreated(demand_id, organization_id, status, demand_version_id)`；
- `DemandVersionCreated(demand_id, demand_version_id, version_no, content_sha256, taxonomy_bundle_id)`；
- `DemandSubmitted(demand_id, demand_version_id, submission_id, status)`；
- `DemandChangesRequested(demand_id, demand_version_id, review_id, reason_codes, required_field_codes, status)`；
- `DemandVerified(demand_id, demand_version_id, review_id, budget_health_code, status)`；
- `DemandFundingRequested(demand_id, demand_version_id, funding_requirement_id, status)`；
- `DemandFunded/DemandFundingReset(demand_id, demand_version_id, funding_id, status)`；
- `MatchingRequested(demand_id, demand_version_id, funding_id, matching_request_id, composite_rule_requirement_id, status)`；
- `DemandMatchingClosedWithoutSelection/DemandMatched/DemandCancelled/DemandExpired` 的最小 ID/status payload。

Funding request事件故意不携带金额、币种、预算或证据；Payments凭 exact requirement ID 通过授权port读取。事件不携带problem/scope/criteria/skills/schedule/budget/risk/AI/data plan、client/legacy ref、assignment人名或自由review note。每封 envelope包含actor/original actor/correlation/causation/trace、organization、aggregate ID/version、UTC时间，且写outbox前以published JSON Schema验证。

Audit保存 action、actor/assignment、target、result、受控 reason codes、版本/hash和correlation；不保存内容或SQL/provider错误。日志、trace、metric label、receipt、dead letter、通知和异常递归禁止：raw Demand content、预算数值、data plan、验收正文、client reference、Idempotency-Key、cookie/CSRF/Session secret、review note、funding/provider evidence与legacy ref。

## 10. PostgreSQL、RLS 与恢复义务

本节的数据库义务已经在 [Demand PostgreSQL fixed-UoW、RLS 与 MATCH_INPUT](/architecture/demand-postgresql.md) 中关闭为独立catalog、角色、fixed program、receipt/inbox、锁序、COMMIT_SENT和真实PG18测试设计；实现与证据以该页为准。

Demand 使用独立 schema/在线角色，至少包含：

- `demand.demands`、`demand.demand_versions`；
- `demand.demand_submissions`、`demand.demand_review_assignments`、`demand.demand_reviews`；
- `demand.demand_funding_markers`、`demand.matching_requests`、`demand.command_receipts`；
- source-event inbox或与共享 durable inbox 的受控复合引用；
- 共享 audit/outbox 的关闭插入入口。

每张组织拥有表显式 `organization_id`，子表使用含 organization/demand/version 的复合外键；owner/client reference digest、version_no、submission/version、active assignment、active funding requirement和OPEN matching request各有精确unique/partial unique。content JSONB只允许应用fixed validator的关闭写入；数据库校验根类型、schema/canonicalization/hash形状和跨表身份，应用写前/读后复算完整 schema/JCS/hash。没有可信JSON Schema extension时不得声称CHECK证明全部content语义。

全部业务表 `ENABLE + FORCE RLS`。在线角色不是owner、无BYPASSRLS：

- `demand_self`只能在 exact authenticated actor/session/organization operation下经 IAM authority marker访问其关系内行；
- `demand_review`只见 exact ACTIVE assignment绑定的submission/version；
- `demand_finance`只见 exact requirement allowlist，不见普通文本内容；
- `demand_matching`只经 exact MatchingRequest读取冻结MATCH_INPUT；
- `demand_system`仍绑定一个 source event/organization/demand/action，不能全表扫描；
- forged custom GUC、跨organization foreign key、失效assignment、失效Session和PUBLIC直连均返回0行或拒写。

Migration必须forward-only、raw-byte SHA-256/review pin、advisory lock、逐文件事务、真实 PostgreSQL 18与wheel packaging；Demand schema不得静默塞入 IAM compatibility view。恢复测试至少覆盖backup/restore后version/hash/receipt/outbox/inbox一致、COMMIT断链、pool scope reset和重放不重复事实。

## 11. 保留、修正与外部启用

被Submission、Review、Funding、MatchRun、Invitation、Selection、Project、争议或审计引用的 DemandVersion 作为不可变交易证据保留；修正只能新建版本。未提交草稿可按版本化保留策略清理，但必须先证明没有receipt或外部引用。Cancel/Expire不是数据删除，退款、争议与法定保留独立处理。

对真实需求、预算、数据计划、资金或候选披露的启用仍受 ADR-0001 的外部门槛约束。测试环境可用合成内容、fake provider与沙箱资金；不得把 Memory/PG GREEN表述为已获准处理真实采购或资金。

## 12. 测试驱动实施顺序

1. 发布独立 Demand OpenAPI、event schema和 `demand-content-v1` JSON Schema；contract测试先钉关闭对象、operation错误、headers、隐私不可表示和内容静态矩阵。
2. 写domain/性质 RED：全状态转换、不可变version/submission/review、hash、日期/金额/bool/percent、终态与随机命令序列。
3. 写Memory application RED：owner/跨组织/assignment/duty、content policy、hold漂移、完整审核、资金source event、matching request、receipt、每写点回滚与commit unknown。
4. 最小Memory GREEN；旧IAM/Profile/MVP保持GREEN，并把RED→GREEN证据写入本页追踪。
5. 先写Demand PostgreSQL/RLS/fixed-query详细实现页，再用真实PostgreSQL18 RED覆盖复合FK、partial unique、伪GUC、跨租户、assignment expiry、source inbox竞争、hash drift与事务断线，最后forward-only GREEN。
6. 实现framework-neutral presenter/HTTP与production composition；以真实PG + IAM Session + outbox + fake content policy/Payments/Matching跑三个角色E2E和秘密sentinel。
7. 只有Demand适用门禁GREEN后，Matching才可将其作为production输入；此前只用显式fake contract，不能读取MVP JSON冒充。

测试不得skip真实依赖、使用owner/BYPASS、关闭RLS、把provider错误包装成成功、放宽关闭schema、从fixture恢复权限，或在production识别test mode。

### 12.1 第一轮 contract/domain/application RED 边界

第一轮只允许提交三份独立机器契约、immutable domain/application facts、依赖ports、默认拒绝handlers和无外部依赖的semantic RED。它明确不实现Memory行为、PostgreSQL、migration、RLS、HTTP/presenter或composition；默认拒绝sentinel必须被测试窄捕获为稳定观察值，使测试以预期业务事实差异失败而不是ImportError、fixture异常或skip。

domain RED至少钉死：关闭/NFC/控制字符/byte bound、JCS/hash签名面、bool金额与percent、合法日期及顺序、版本追加与不可变、exact submission/review绑定、终态不可回退。application RED至少钉死Create、CreateVersion、Submit、RequestChanges、Verify、Funding source event、RequestMatching、Cancel、Expire，以及exact IAM organization authority、assignment+duty职责分离、content-policy和hold drift重评、receipt replay/different payload、每个稳定checkpoint全回滚、COMMIT_SENT结果未知恢复与秘密不可观察。

本轮有效RED不得靠缺production symbol制造；所有公开surface必须可导入、不可变且默认拒绝。contract tests必须先GREEN，并证明API/event/content对象关闭、隐私字段不可表示和全部引用可解析。

### 12.2 第一轮 RED 实证（2026-08-08）

已提交且只覆盖本轮边界的文件为：

- `contracts/api/demand-v1.openapi.yaml`、`contracts/events/demand-v1.schema.json`、`contracts/domain/demand-content-v1.schema.json`；
- `desire_platform.demand.domain.model`的immutable entities和default-deny domain surface；
- `desire_platform.demand.application.commands/handlers`及`desire_platform.demand.ports.commands`的immutable commands、关闭ports和default-deny handlers；
- 独立`tests/contract/test_demand_contracts.py`、`tests/demand/test_demand_domain_red.py`、`tests/application/test_demand_commands_red.py`与`tests/support/demand_builders.py`。

精确执行证据：

```text
PYTHONPATH=src:tests .venv/bin/python -m unittest contract.test_demand_contracts -v
Ran 7 tests — OK

PYTHONPATH=src:tests .venv/bin/python -m unittest demand.test_demand_domain_red -v
Ran 11 tests — FAILED (failures=10, errors=0, skipped=0)

PYTHONPATH=src:tests .venv/bin/python -m unittest application.test_demand_commands_red -v
Ran 16 tests — FAILED (failures=16, errors=0, skipped=0)
```

domain唯一GREEN项只证明dataclass不可变且`repr`隐藏content/evidence；十个RED分别来自内容关闭/规范、bool金额与percent、日期与AI/data联动、提交完整性、JCS/hash、创建/版本追加、version不可变复算、submission exact binding、review exact binding、root pointer/终态规则尚由稳定`DEMAND_DOMAIN_BEHAVIOR_NOT_AVAILABLE`拒绝。application十六个RED覆盖九个命令成功事实以及exact owner authority、assignment+duty职责分离、content-policy/hold/rule drift、receipt replay与different payload、十三个稳定checkpoint回滚、COMMIT_SENT恢复和秘密隔离；失败只来自期望业务结果与稳定`DEMAND_APPLICATION_BEHAVIOR_NOT_AVAILABLE`的差异，不是ImportError、fixture异常、skip、数据库或网络环境。

本状态只授权下一轮最小Memory GREEN；不得据此宣称PostgreSQL、RLS、HTTP、process manager或production composition已实现。

### 12.3 第二轮 Memory RED → GREEN 实证（2026-08-08）

相同11项domain与16项application方法未删除或放宽业务断言，现已全部GREEN。production domain实现关闭/NFC/control/UTF-8 byte验证、非bool金额/percent、合法日历日期、完整性与跨字段规则、规范JCS/SHA-256、append-only version/submission/review和终态；测试fixture不再用形状合法但内容错误的`bbbb…`占位hash，完整fixture的真实digest为`ca36a46e6af1a343fbad136b548d5bf63efb00da95985db5aa931f469c4841b5`，保存、提交与审核仍独立复算。

Memory application实现：

- exact actor/session/organization/Membership/`DEMAND_OWNER` authority，以及exact assignment、`OPERATIONS_REVIEWER` duty、expiry和creator/owning-org职责分离；
- Submit content-policy、Submit/Verify/RequestMatching SafetyHold及current rule requirement的事务外评估和锁内root/version/hash重新绑定；binding损坏503、taxonomy漂移409、BLOCK 403，均零写；
- raw Idempotency-Key和client reference只进入域分离keyed digest，receipt identity/payload hash、same-key replay、different-payload冲突及关闭safe response的target/organization/version/status/ETag完整绑定；
- root、append-only facts、receipt/source inbox、audit和正式schema验证后的outbox在一个Memory UoW提交；十三个稳定checkpoint逐个故障均恢复完整pre-command snapshot；
- COMMIT已发送但ack丢失时只从独立store snapshot恢复完整COMPLETED且payload/target/version/safe response一致的receipt；IN_PROGRESS、缺失或损坏结果统一503，不猜测成功；
- command/entity repr、receipt、audit、outbox、validator observations和异常均不包含raw content、client reference、Idempotency-Key、Session/CSRF、review narrative或provider evidence。

精确执行证据：

```text
PYTHONPATH=src:tests .venv/bin/python -m unittest \
  contract.test_demand_contracts \
  demand.test_demand_domain_red \
  application.test_demand_commands_red -v
Ran 34 tests — OK

# 全部非PostgreSQL application/authentication/authority/authorization/
# contract/http/policy-consent/read-model discovery
Ran 285 tests — OK
```

本轮是Memory行为证据，不证明数据库constraint、真实并发、RLS、physical connection disposition、HTTP header/parser或部署装配；第10节与第12节第5/6步仍保持planned，下一阶段必须先另写Demand PostgreSQL详细实现设计和真实PG18 RED。

## 13. REQ → DESIGN → TEST → CODE

| REQ | DESIGN | 验收 TEST | CODE | 状态 |
| --- | --- | --- | --- | --- |
| `REQ-DEMAND-001` | DES-DEMAND-001 · §2/4 | `TEST-UNIT-DEMAND-001` | `demand.domain.model` | green · domain 11/11 |
| `REQ-DEMAND-002` | DES-DEMAND-002 · §3/3.1 | `TEST-CONTRACT-DEMAND-001`, `TEST-PROP-DEMAND-001` | `demand-content-v1.schema.json`; `demand.domain.model` | green · contract/domain |
| `REQ-DEMAND-003` | DES-DEMAND-003 · §5/8 | `TEST-AUTH-DEMAND-001`, `TEST-API-DEMAND-001` | `demand.ports.commands`; `demand.application.handlers` | green · Memory authority；HTTP planned |
| `REQ-DEMAND-004` | DES-DEMAND-004 · §4/5 | `TEST-APP-DEMAND-REVIEW-001` | `demand.application.handlers` | green · assignment/duty/review |
| `REQ-DEMAND-005` | DES-DEMAND-005 · §4 | `TEST-APP-DEMAND-FUNDING-001`, `TEST-APP-DEMAND-MATCHING-001` | `demand.application.handlers` | green · source event/frozen request |
| `REQ-DEMAND-006` | DES-DEMAND-006 · §6 | `TEST-APP-DEMAND-RECEIPT-001`, `TEST-DB-DEMAND-CONCURRENCY-001` | `demand.application.handlers`; `demand.ports.commands` | green · Memory receipt/checkpoint/unknown-COMMIT；DB planned |
| `REQ-DEMAND-007` | DES-DEMAND-007 · §8/9 | `TEST-SEC-DEMAND-DISCLOSURE-001`, `TEST-EVENT-DEMAND-001` | `demand-v1.schema.json`; immutable secret-safe facts/handlers | green · event/application privacy |
| `REQ-DEMAND-008` | DES-DEMAND-008 · §10 | `TEST-DB-DEMAND-RLS-001`, `TEST-E2E-DEMAND-001` | planned | design |
| `REQ-DEMAND-009` | DES-DEMAND-009 · §2/11 | `TEST-RECOVERY-DEMAND-001` | planned | design |

状态只能在有效RED后改为red，在相同断言与适用回归GREEN后改为green；实现文件必须回填精确模块与migration版本。
