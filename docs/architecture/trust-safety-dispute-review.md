# Trust、SafetyHold、Dispute、Appeal 与 Review

> 状态：Trust & Review Context 的权威详细设计；INTERNAL_SANDBOX 已落地 Trust17 的 Demand 举报、最小当事人读取、Trust Officer 分配处置、party-safe 本人完成历史与 Appeal 纵切，其余范围仍是设计。本文不构成法律建议、处罚政策或真实案件处理授权。
> 适用范围：SafetyHold判定、私密Report、争议/调解/裁决/申诉、范围化救济、双盲Review、证据访问、职责分离、事件与RLS。
> 前置依赖：[目标平台领域模型](/architecture/platform-domain-model.md)、[IAM](/architecture/identity-tenancy-consent.md)、[Project/Agreement](/architecture/project-agreement-delivery.md)、[Funding](/architecture/funding-and-payment-projection.md)与[ADR-0001](/decisions/0001-platform-scope-and-delivery.md)。

## 1. 原则、事实所有权与非目标

Trust & Review Context负责把安全限制、举报、合同争议、程序性裁决/申诉和项目后反馈建模为不同事实。它拥有 `SafetyHold`、`Report`、`TrustCaseAssignment`、`EvidenceItem/AccessGrant`、`Dispute`、`MediationProposal`、`Ruling`、`Appeal` 与 `Review`。

它不拥有User/Organization角色、Project/Milestone/Payment主状态，也不直接改其他Context表。Hold通过同步窄判定阻止受保护动作；Dispute/Ruling/Appeal的业务后果由关闭命令event和幂等process manager应用。通知、搜索或人工工单不能成为处罚/裁决事实来源。

核心原则：

- 安全降权（logout、撤销、暂停、举报、放置紧急hold、拒绝/withdraw）不能被已有hold阻止；
- hold只阻止明确action/resource范围，不以一个局部争议冻结全部账户/项目/资金；
- 当事人有被告知、陈述、证据访问、回避和申诉机会，但通知必须遵守安全/法律例外；
- mediator不单独裁决，ruling panel成员无冲突且满足法定人数，appeal reviewer不参与原处理；
- AI只可做受控分类、去重建议、摘要草稿和证据索引；不能IssueRuling、DecideAppeal、永久处罚或自动公开评价；
- 举报/证据正文、身份、健康/安全信息不进入普通业务表、事件、日志或训练数据。

## 2. SafetyHold 聚合与判定

### 2.1 Hold scope

SafetyHold状态 `ACTIVE / RELEASED / EXPIRED`，至少保存：

| 字段 | 规则 |
| --- | --- |
| `id/type` | type为 `SAFETY / LEGAL / PAYMENT / IDENTITY / CONTENT / DISPUTE` |
| `subject_kind/id` | 可空的USER/ORGANIZATION主体；不能用contact定位 |
| `resource_type/id/version_floor?` | 可空的exact资源；scope shape必须由policy允许 |
| `organization_id` | 有租户语义时必填且与resource复合一致 |
| `action_codes` | 从版本化action registry选择的非空集合；不接受glob/自由字符串 |
| `effect` | 首版只为`BLOCK`；没有允许override的负向hold |
| `reason_code/severity` | 关闭code；自由叙述留在受限case note |
| `source_type/id/version` | Report/Dispute/Ruling/ProviderEvent/ManualCase等exact来源 |
| `effective_at/expires_at` | UTC半开窗口；`expires_at <= db_now`立即失效 |
| `policy_version` | action匹配/组合/时效规则版本 |
| `aggregate_version/released_at/released_by` | 状态证据；不物理删除 |

scope使用关闭判别联合：`SUBJECT_ACTIONS`、`ORGANIZATION_ACTIONS`、`RESOURCE_ACTIONS`、`RESOURCE_SUBTREE_ACTIONS`。subtree只允许policy明列关系，例如Project→其Milestone/Delivery；禁止任意prefix/path。Global全平台hold仅用于明确User主体及action集合，要求更高职责/审批，不能以空target表示“阻止所有人”。

同一source/scope/action-set有业务唯一性；重复issue重放同一hold。多个ACTIVE hold按并集BLOCK；release一个不能覆盖其他hold。

### 2.2 Rich decision protocol

`SafetyHoldDecisionPort.evaluate` 输入固定：

```text
actor_id, action, target_type, target_id, target_version,
organization_id?, policy_version, correlation_id
```

输出不可变 `SafetyHoldDecisionResult`：

```text
decision = ALLOW | BLOCK | UNAVAILABLE
exact回传全部query绑定字段
decision_id, evaluated_at, valid_until(exclusive)
matched_hold_count
reason_code?              # BLOCK时安全、宽泛code
snapshot_version/digest
```

调用方逐字段constant semantic compare，只在 `evaluated_at <= server_now < valid_until` 使用；future time、deadline等号、错action/target/version/org/policy、未知decision、missing key/provider或持久快照损坏均UNAVAILABLE。BLOCK不返回hold/case/report ID或具体举报理由。

ALLOW不是永久capability。调用方锁内发现actor/resource/version/policy/snapshot drift时必须回滚，在事务外以新事实重评；provider调用不进入UoW/retry closure。completed idempotent receipt replay不再调用hold，但仍验证当前ACTIVE Session和receipt完整绑定；是否允许重放安全response不产生新authority。

Trust服务不可用对增权/披露/资金动作fail closed 503；安全降权动作不调用port。查询读取可以按敏感度选择deny/no-store，但不能把unavailable当ALLOW。

### 2.3 Issue、review、release

`PlaceSafetyHold`可由assigned TRUST_OFFICER、认证provider security event或Dispute创建流程执行。紧急、短TTL hold可单人放置以先降权；超过policy时长、扩大scope、账户级或payment release hold必须在deadline前由第二名无冲突TRUST_OFFICER review，否则自动EXPIRED。

`ReleaseSafetyHold`要求source已解决/纠正、exact review assignment、reason code和必要双人确认；issuer不能单独释放自己创建的高风险hold。release是新事实，不删除。系统定时 `ExpireSafetyHold`以database clock执行并重新检查source没有续期；续期创建新version/hold，不原地改expires。

## 3. 私密 Report

Report用于安全、骚扰、泄密、欺诈、报复或平台行为举报，不是公开Review或合同Dispute的替代。状态：

`OPEN / TRIAGED / INVESTIGATING / ACTION_REQUIRED / RESOLVED / DISMISSED / CLOSED`。

公开intake body关闭为：report category/severity、target resource/subject opaque ID可空、incident time window、structured impact codes、受控Evidence IDs、safe contact preference code。叙述正文通过独立sealed narrative service存储；Report表只存digest/object reference、KMS key ID和retention class。匿名/未登录举报若未来启用必须另设计rate limit、capability与回访，不在首版悄悄开放。

Report可触发最小临时hold，但“被举报”本身不证明违规。Triage保存priority/jurisdiction/assignment requirements；Dismiss仍保留程序证据。被举报者的披露取决于case policy/安全风险，普通API始终不暴露reporter identity、contact、其他Report或内部severity。

### 3.1 INTERNAL_SANDBOX 的当事人发现闭环

Trust9 为 Organization 工作区中的 `DEMAND_OWNER` 提供
`GET /v1/app/trust/reports?limit=20&cursor=...`。actor、Organization 与
`READ_OWN_REPORT` authority 全部由当前 Session/IAM 服务端派生；游标由独立
`TRUST_REPORT_CURSOR` HMAC keyring 签名，并绑定 actor、Organization、page size 与
keyset boundary。换用户、换 Organization、改 page size、篡改或使用退休 key 都必须失败关闭。

列表只含 category、Demand/Report ID、状态、提交时间，以及已发布结论的最小 outcome code、
版本、时间和申诉资格/截止。它不含叙事、证据引用或内容、报告人身份、内部理由/动作、policy、
digest 或受限备注。PostgreSQL 函数在 IAM authority 成功后，按
`(created_at DESC, report_id ASC)` 做 `limit + 1` keyset 查询，并再次精确过滤
reporter 与 Organization；底表继续 ENABLE+FORCE RLS，`trust_self` 只有函数 EXECUTE、没有表 SELECT。

Web 首次进入、手动刷新和重新登录后都从该列表重新发现；翻页会拒绝重复 ID、顺序倒退与游标环。
点击列表项时仍按 exact Report ID fresh GET，列表摘要不能直接成为详情或 Appeal 依据。提交成功后，
客户端同时 fresh GET 精确详情和列表首页，并要求新 Report 可被服务端重新发现后才更新 UI。
读取失败保留此前完整验证的列表且明确显示不可用，不把失败伪装为零条记录。

### 3.2 Trust Officer 的终态案件发现

Trust11 已把本人作出终态决定的案件收敛为 actor-bound PostgreSQL 投影；Trust17 将它正式发布为
`GET /v1/app/trust/history`。请求只接受当前 `platform:<user_id>` 工作区、空 query 与空 body，服务端固定读取
最近 100 条并返回 `has_more`，不把分页大小变成客户端可调的探测面。每项只有 `case_id`、`decided_at` 与关闭的
`outcome_code`；assignment、其他处理人、Duty/IAM 坐标、Organization、Demand、举报、证据和内部处置理由均不披露。

读取在数据库内重新证明当前 ACTIVE Session、当前 `TRUST_OFFICER` duty、决定人和原 `CASE_TRIAGE`
assignment 都属于同一 actor；底表继续 ENABLE+FORCE RLS。结果按决定时间倒序、同一时间按 Case ID 倒序，拒绝重复
Case，带强 ETag 且 `no-store`。超过固定窗口只明确显示“还有更早记录”，UI 不得谎称这是完整历史。

任务投影中的 completed Trust Case 只把用户导航到这个本人历史集合，并用任务携带的 exact Case ID 聚焦对应行；它
不得再链接只对活动 assignment 可读的 `/v1/app/trust/cases/{case_id}`。页面切换 Session/User、工作区或从任务卡进入时
都 fresh bootstrap、fresh workspace、fresh task 与 fresh history；目标行未被当前 actor 的历史重新发现时，按不可披露
处理，不回退到活动案件详情，也不显示任务缓存中的终态事实。

## 4. 证据与访问

`EvidenceItem`只存case、kind、source resource/version/hash、sealed object ID、submitter party、captured_at、integrity/scan/provider attestation与retention class。业务Context的不可变Agreement/Delivery/Payment等证据通过exact version/hash引用，不复制正文。

每次读取需要 `EvidenceAccessGrant`：case、assignee/party、purpose、field/category allowlist、effective/expires、issuer、legal/safety redaction profile。grant不允许转授权；下载用single-item短期capability，sensitive/no-store/redact。访问追加审计。

当事人材料披露使用不可变 `EvidencePacketVersion`，保存included item/hash/redaction profile/created_at。双方获得的packet可不同，但差异必须由关闭withholding reason与review审批解释；裁决只能引用panel有权访问且程序允许的packet版本。

## 5. Dispute、Mediation 与 Ruling

### 5.1 Dispute

Dispute状态沿用：`OPEN / EVIDENCE_COLLECTION / MEDIATION / RULING_PENDING / RULED / APPEAL_PENDING / RESOLVED / CLOSED`。它绑定exact Project/AgreementVersion，可选Milestone/Delivery/Acceptance/Funding/Payment与争议scope hash。

OpenDispute要求actor是exact Project party/representative、仍在版本化window、争点/请求/协议条款codes与最低Evidence refs完整。同事务创建最小scope SafetyHold，例如只阻止某Milestone auto-accept/release，不阻止无关里程碑或原付款方退款。

assignment由TRUST_OFFICER创建，处理人披露与所有party/org/project的冲突；有冲突或参与过相关review/funding/operation者不可担任mediator/panel/appeal reviewer。

### 5.2 Mediation

MEDIATOR可在双方获得规定EvidencePacket后开始。`MediationProposal`内容关闭：争点逐项处理、非承认条款code、范围/时间/amount consequence、required parties、expiry与hash。双方以party authority确认同一hash；最后一方确认使Dispute→RESOLVED并发 `DisputeSettled`，但实际Project/Funding变化由process manager执行。

Mediator不能单方接受proposal或发布Ruling。未成时冻结 `RulingRecord` 的issues/evidence packet/rule bundle并进入RULING_PENDING。

### 5.3 Ruling

Ruling由一个版本化panel assignment集合决定，要求policy定义的quorum、每名成员ACTIVE `RULING_PANEL` duty、无冲突且不是mediator/triager/当事人。每名panel vote对 `(ruling_id, member_id)` 唯一，内容为closed outcome/reason/relief codes和evidence references；无自由秘密进入普通表。

达到quorum后用确定性policy计算result并保存不可变 `RulingVersion`：

- issues与finding codes；
-引用Agreement/rule/evidence packet版本；
- closed remedies：`ACCEPT_DELIVERY / REQUIRE_REWORK / CANCEL_MILESTONE / RELEASE_AMOUNT / REFUND_AMOUNT / NO_CHANGE / CORRECT_RECORD / TEMPORARY_RESTRICTION`及精确参数；
- appeal eligibility/deadline与execution plan IDs；
- content/canonical hash、panel/quorum policy version。

Ruling不能直接执行SQL修改Project/Payments。`IssueRuling`使Dispute→RULED并发送closed commands；process manager逐Context幂等执行。金额/currency必须在Agreement/Funding边界内，超出则validation fail而非自由裁量写负数。

## 6. Appeal

每个可申诉Ruling默认至多一个Appeal，状态 `DRAFT / SUBMITTED / UNDER_REVIEW / DECIDED / DISMISSED`。允许理由只为：

`PROCEDURAL_ERROR / NEW_MATERIAL_EVIDENCE / RULE_MISAPPLICATION`。

不接受“对结果不满”的开放第二次全案重审。Submit绑定exactRuling hash、grounds、请求、new evidence refs与deadline；deadline等号已逾期。

Appeal assignment中的APPEAL_REVIEWER/独立panel不能参与原triage、mediation、ruling或相关finance decision。review只访问原record与允许new evidence。决定closed为 `AFFIRM / MODIFY / VACATE_AND_REMAND / DISMISS`，保存原因/引用/remedy delta/hash与quorum。ApplyAppealDecision生成新执行计划，不改写原Ruling；Dispute保留完整链。

## 7. Review 与私密反馈

Review只在Project COMPLETED/CANCELLED后创建，状态 `PENDING / SUBMITTED / EXPIRED / REVEALED / WITHHELD / REDACTED`。每个author party→recipient party每Project至多一条。

内容分离：

- `factual`：按协议沟通、时效、scope clarity、acceptance process等受控yes/no/ordinal codes；
- `experience`：受控维度和可选短文本，经过内容/PII policy；
- `private_platform_feedback`：永不向对方公开，仅用于受限改进；安全举报必须另CreateReport；
- 不计算/展示单一五星总分，不接受受保护属性、contact、私密金额、case/evidence细节或报复威胁。

双盲：双方都SUBMITTED或window结束后才Reveal；单方未提交时已提交者在window结束可揭示，但需反报复策略。ACTIVE hold可WITHHOLD；TRUST_OFFICER只能按政策redact违法/泄密内容，原文作为restricted evidence保留并产生correction record。被评价者可对程序/泄密提出Report/appeal-like review challenge，不能直接改写评价。

Review不直接进入matching score。任何未来声誉/展示/匹配使用必须新设计统计、公平、反操纵、最小样本与纠错，不能读取Review表临时加权。

## 8. 授权、API、幂等和错误

公开/受控API示例：

```text
POST /v1/projects/{project_id}/disputes
GET  /v1/me/disputes/{dispute_id}
POST /v1/disputes/{dispute_id}/evidence
POST /v1/disputes/{dispute_id}/mediation-proposals/{proposal_id}/accept
POST /v1/disputes/{dispute_id}/appeals
POST /v1/me/reports
GET  /v1/me/reviews
POST /v1/reviews/{review_id}/submit

POST /v1/trust/reports/{report_id}/triage
POST /v1/trust/cases/{case_id}/assignments
POST /v1/trust/holds
POST /v1/trust/holds/{hold_id}/release
POST /v1/trust/disputes/{id}/begin-mediation
POST /v1/trust/disputes/{id}/request-ruling
POST /v1/trust/rulings/{id}/votes
POST /v1/trust/appeals/{id}/decide
```

所有party命令要求ACTIVE Session/IAM policy + exact Project/Dispute/Review relationship。平台职责要求time-bound case assignment/purpose/conflict。ORG_ADMIN/PROJECT_MEMBER/TRUST_OFFICER角色本身都不是任意case/evidence访问权。SYSTEM绑定exact source event/case/execution plan。

外部写Idempotency-Key + aggregate If-Match；create用receipt+source/client reference digest唯一。body不接受actor/role/status/decision time/hash/other party identity。receipt不存narrative/evidence/file capability/raw reason。

Safety降权/Report intake/PlaceHold不受SafetyHold阻止；ReleaseHold、RevealReview、Resume action、settlement/ruling execution等增权/披露动作按自身hold/policy复核，避免循环调用同一hold使无法解除。release的授权由Trust规则/双控决定，而不是普通业务port。

锁序：case/report → assignments按User ID → hold按ID → Dispute → evidence packet/item按ID → mediation/ruling/panel votes → Appeal → Review → execution plan/source inbox → receipt。多方确认按party ID规范序。每写点checkpoint、audit/outbox一次COMMIT；commit unknown全链读取。

wire code：400 invalid；401 auth/session；403 access/hold；404 non-disclosure；409 state/idempotency/assignment/packet/ruling/hold snapshot changed；412 stale；422 `CASE_VALIDATION_FAILED/EVIDENCE_REQUIRED/CONFLICT_OF_INTEREST/QUORUM_NOT_MET/APPEAL_NOT_ELIGIBLE/REVIEW_CONTENT_REJECTED`; 503 policy/key/storage/service unavailable。对外不返回“report exists”“who reported”“which panel member blocked”。

## 9. 事件、隐私、保留与透明度

事件只携带opaque case/resource IDs、状态、scope/action codes、aggregate version、deadline和执行计划ID。SafetyHoldPlaced/Released事件不含reporter/reason narrative；Dispute/Ruling/Appeal不含evidence、vote、amount详情或party statements；ReviewSubmitted不含内容，ReviewRevealed只表示可按授权重读。

每个执行后果使用独立closed command/event，例如 `MilestoneRulingApplied`、`RefundAuthorized`，并由目标Context再次验证其边界。通知只发安全模板与portal link，不在邮件中写争议/举报/裁决正文。

证据、narrative、原review与审计有版本化retention/legal hold。普通删除请求不能删除开放case证据；case关闭后按类别删除/去标识，保留最小程序/纠正事实。访问/导出经过case-specific redaction和审计，不提供一个“下载所有trust数据”的无差别函数。

平台发布聚合透明度指标时使用最小样本、去标识bucket，不按个人/小组织暴露report/hold/ruling。模型训练默认排除Trust正文；任何研究使用需独立consent/ethics/data contract。

## 10. PostgreSQL 与RLS

独立 `trust` schema至少包含holds、reports、cases/assignments、evidence metadata/access grants/packet versions、disputes、mediation proposals/confirmations、rulings/panel assignments/votes、appeals/decisions、reviews、execution plans、receipts/source inbox。sealed narrative/evidence只保存opaque object reference/digest/key ID。

约束：hold scope判别shape/action非空；ACTIVE时间shape；source/scope业务唯一；case assignment conflict/expiry；evidence/packet复合一致；一Dispute一开放Mediation/Ruling；quorum/unique vote；一Ruling一Appeal；Review author/recipient/project唯一且不同party；状态/时间/required hash。

全部ENABLE+FORCE RLS。party只见exact case中获准投影；assignee只见purpose/field allowlist；panel只见其ruling packet；appeal reviewer只见appeal record；Safety decision role只能调用固定evaluate函数且不能读hold/report表；PUBLIC无EXECUTE/SELECT，线上角色非owner/无BYPASS。

`trust_api.evaluate_safety_hold_v1`必须固定search_path、静态SQL、验证session_user/current_user/调用role与exact query shape，只返回rich decision allowlist。防止调用者通过遍历target枚举hold；BLOCK/ALLOW响应大小和错误尽量一致。伪GUC、跨case、过期assignment/grant、wrong resource version均拒绝。

Migration forward-only/digest/review pin、真PG18 RLS/constraint/concurrency和wheel。备份恢复必须保持sealed object/digest、hold、case state、execution inbox/outbox一致。

## 11. TDD 与追踪

1. 发布Trust OpenAPI、event、hold/report/evidence/ruling/appeal/review closed schemas；privacy contract RED→GREEN。
2. Domain/性质RED覆盖hold scope/组合/expiry、Dispute/Appeal/Review状态、quorum/conflict、双盲和终态。
3. Memory application RED覆盖rich hold错绑定/TTL/drift、report/assignment、evidence access、多方mediation/ruling/appeal、execution plans、receipt/fault/commit unknown。
4. 最小GREEN；AI接口只能输出草稿且无法调用decision command。
5. PG/RLS设计后真PG18 RED覆盖case隔离、decision non-enumeration、伪GUC、quorum/deferred constraints、double appeal/reveal、source execution去重。
6. Project/Payments process E2E证明局部hold、ruling/appeal后果、乱序/重复与通知失败不破坏事实。
7. 真实启用前完成人员培训、SLA、外部救济、法律/安全审批与人工演练。

| REQ | DESIGN | TEST | CODE | 状态 |
| --- | --- | --- | --- | --- |
| `REQ-TRUST-001` | DES-TRUST-001 · §2 | `TEST-UNIT-HOLD-001`, `TEST-APP-HOLD-001`, `TEST-DB-HOLD-RLS-001` | planned | design |
| `REQ-TRUST-002` | DES-TRUST-002 · §3/4 | `TEST-CONTRACT-REPORT-001`, `TEST-AUTH-EVIDENCE-001` | planned | design |
| `REQ-TRUST-003` | DES-TRUST-003 · §5 | `TEST-APP-DISPUTE-001`, `TEST-APP-RULING-001` | planned | design |
| `REQ-TRUST-004` | DES-TRUST-004 · §6 | `TEST-APP-APPEAL-001` | planned | design |
| `REQ-TRUST-005` | DES-TRUST-005 · §7 | `TEST-APP-REVIEW-001`, `TEST-SEC-REVIEW-001` | planned | design |
| `REQ-TRUST-006` | DES-TRUST-006 · §8/9 | `TEST-APP-TRUST-RECEIPT-001`, `TEST-EVENT-TRUST-001` | planned | design |
| `REQ-TRUST-007` | DES-TRUST-007 · §10 | `TEST-DB-TRUST-RLS-001`, `TEST-RECOVERY-TRUST-001` | planned | design |

只有有效RED后才标red；相同断言、适用回归和真实依赖GREEN后才标green。真实案件启用还需独立外部审批证据。
