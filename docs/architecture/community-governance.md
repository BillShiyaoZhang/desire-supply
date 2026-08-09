# Community、Contribution 与规则治理

> 状态：Community & Governance Context 的权威详细设计；机器契约和可执行 RED 尚未提交，真实社区/投票默认关闭。  
> 适用范围：领域Group、成员资格、Contribution、同行评议、RuleProposal、投票/决议、公共知识发布与业务规则发布隔离。  
> 非目标：让投票直接修改交易规则、IAM角色、资金、处罚或production配置。

## 1. 边界与治理原则

Community Context拥有 `CommunityGroup`、`GroupMembership`、`Contribution/Version`、`PeerReview`、`RuleProposal/Version`、`GovernanceBallot/Vote/Decision` 与 `KnowledgeArtifact`。它不拥有Organization Membership、业务Context规则包、Project、Payment或Trust处罚。

社区资格是独立关系，不授予ORG_ADMIN/OPERATIONS/FINANCE/TRUST权限。Group被关闭或成员被撤销不改写其历史业务角色。反之，拥有平台角色也不会自动成为治理成员。

治理输出是建议/候选artifact：即使proposal被ACCEPTED，也只能生成 `RuleCandidatePublished`。相应业务Context仍需其独立签名、评测、legal/safety review、职责分离和Publish命令；Community worker没有那些credential。

首版不启用代币、付费投票、可交易声誉、匿名公开发帖、无限群组、实时聊天或算法推荐feed。真实启用需反滥用、内容治理、维护者培训与申诉流程。

## 2. CommunityGroup 与 Membership

Group状态 `DRAFT / ACTIVE / PAUSED / CLOSED`，保存purpose/domain/taxonomy、jurisdiction/locale、charter version/hash、membership policy、governance policy、moderation policy与aggregate version。

Membership状态 `PENDING / ACTIVE / SUSPENDED / LEFT / REVOKED`，role关闭为 `MEMBER / REVIEWER / STEWARD`。一个User可多Group；role只在该Group有效。入组来源：受控邀请/申请+policy eligibility；不从Project参与自动公开推导。

STEWARD管理内容/流程，不可修改投票、业务规则或Trust case。last active steward、self-review、conflict和任期边界受约束。暂停/撤销是降权不受SafetyHold阻止；恢复/晋升需hold、近期auth和独立审批。

Group charter变更使用不可变version和成员/平台双层批准，不能原地编辑使旧vote含义漂移。

## 3. Contribution 与同行评议

Contribution状态 `DRAFT / SUBMITTED / UNDER_REVIEW / ACCEPTED / REJECTED / WITHDRAWN / PUBLISHED / RETIRED`，kind为 `PRACTICE_NOTE / TAXONOMY_SUGGESTION / CASE_STUDY / TOOLING / RESEARCH_SUMMARY`。

每次编辑创建append-only `ContributionVersion`，closed内容包含title/summary/structured claims/source citations/allowed attachments/license/data provenance；正文使用安全AST。禁止contact、participant/project可识别细节、私密预算、Agreement/Trust证据、未获授权文件或第三方token。case study必须使用approved de-identification manifest与source permission。

Submit冻结content hash、license、source/provenance与review criteria。PeerReview assignment要求REVIEWER、无作者/组织/项目冲突；至少policy数量的不同reviewer。review只用closed recommendation/criterion codes和可选受限note。最后决定由STEWARD按published policy执行，不能伪造reviewer共识。

PUBLISHED KnowledgeArtifact是单独immutable公开/成员投影，经过内容安全、版权/许可、PII泄漏与link policy。source Contribution后续更正通过新artifact version或Retire，不覆盖旧hash。PUBLIC发布首版feature flag关闭。

## 4. RuleProposal

RuleProposal只针对published `governable_surface`：taxonomy、matching reason/weight建议、community charter/template等。身份/法律policy、SafetyHold、资金、Trust裁决、访问控制不能由普通proposal直接治理，除非未来新ADR定义更高程序。

状态 `DRAFT / SUBMITTED / DELIBERATION / BALLOT / ACCEPTED / REJECTED / WITHDRAWN / EXPIRED / CANDIDATE_PUBLISHED`。

closed proposal version包含：target surface/current version、problem statement、安全change set、expected impact、compat/migration plan、evaluation plan、affected parties、conflicts、source contributions、content hash。change set不是任意JSON Patch；每surface有schema/validator。

提交时验证proposer membership/tenure/contribution eligibility；同target同base不能有重叠active proposal除非明确supersedes。base漂移使proposal需rebase新version，不能把旧vote应用到新内容。

## 5. Ballot、Vote 与 Decision

Ballot在进入BALLOT时冻结：proposal version/hash、eligible voter set/digest、quorum/threshold/counting policy、open/close DB times、conflict/exclusion set与anonymity mode。

- 每eligible User一vote；不按Organization账号、贡献次数或资金加权，除非future policy显式设计；
- vote只为 `APPROVE / REJECT / ABSTAIN`，append-only；在close前允许新version替代自己的旧vote并保留历史；
- voter eligibility在snapshot冻结，之后被安全撤销可由policy作废但必须记录；不能临时增加友好voter；
- proposer/steward可投与否由policy固定；利益冲突者excluded；
- close equality已截止，SYSTEM定时count；整数/quorum确定性，tie规则预发布；
- Decision保存counts、eligible/quorum、policy/proposal/voter-set hashes和结果，不公开individual vote（若secret ballot）；
- 审计可验证一个eligible主体最多一个effective vote，但普通成员不能反推他人选择。

ACCEPTED只使proposal可生成candidate artifact。`PublishRuleCandidate`验证decision、base仍current、change/evaluation artifact一致，输出signed candidate给目标Context；目标publisher独立接受或拒绝。Community不能把candidate标ACTIVE。

## 6. Moderation、Report 与Appeal

内容举报通过Trust Report或Community moderation case，后者只处理Group内容/行为且可升级Trust。Moderation动作closed为 `HIDE_CONTENT / LOCK_THREAD / PAUSE_MEMBERSHIP / RESTORE / RETIRE_ARTIFACT`，scope最小、期限/原因/assignment明确。

STEWARD不能处理自己的内容/举报、不能查看Trust reporter identity，也不能永久平台处罚。高风险动作需第二steward或Trust。作者/成员可对程序错误、错误内容匹配、新证据提出一次appeal，由未参与者处理；不直接编辑原decision。

## 7. API、授权、幂等与隐私

```text
GET  /v1/community/groups
GET  /v1/community/groups/{group_id}
POST /v1/community/groups/{group_id}/memberships/apply
POST /v1/community/groups/{group_id}/contributions
POST /v1/community/contributions/{id}/versions
POST /v1/community/contributions/{id}/submit
POST /v1/community/reviews/{id}/submit
POST /v1/community/groups/{group_id}/rule-proposals
POST /v1/community/rule-proposals/{id}/submit
POST /v1/community/ballots/{id}/votes
POST /v1/community/rule-proposals/{id}/withdraw
POST /v1/operations/community/rule-candidates/{id}/publish
```

actor来自BFF；exact Group Membership/assignment、policy/consent/hold与resource关系每次验证。外部写Idempotency-Key+aggregate If-Match。unknown/private group/content/nonmember统一404。

公开projection只含ACTIVE group与PUBLISHED artifact的approved fields；成员投影按role；review/vote/conflict/moderation notes单独。消息/正文不进入event/log/notification preview。个人投票、membership eligibility、项目来源、Trust case、contact和身份不进入public API。

wire：基础400/401/403/404/409/412/422/503，特有422 `MEMBERSHIP_NOT_ELIGIBLE/CONTRIBUTION_VALIDATION_FAILED/PROPOSAL_VALIDATION_FAILED/QUORUM_NOT_MET/CONFLICT_OF_INTEREST`; rate 429。

## 8. 事件、PostgreSQL/RLS 与恢复

事件只含group/membership/contribution/proposal/ballot/artifact opaque IDs、status/version/hash、controlled kind/outcome/deadline/counts；不含正文、individual vote、review/note、conflict或source private resource。业务Rule Context只消费RuleCandidatePublished并重新授权/验证。

`community` schema包含groups/charters/memberships、contributions/versions/reviews/assignments、proposals/versions/ballots/voter snapshots/votes/decisions、artifacts/moderation/receipts。全部FORCE RLS：public只走security-barrier published views；member/reviewer/steward按exact关系/assignment；ballot counter只见exactclosed ballot；candidate publisher只见accepted artifact。PUBLIC无base table/unsafe function，online非owner/无BYPASS。

约束：one active membership、last steward、append versions、review uniqueness/conflict、proposal/base/change identity、frozen voter set、one effective vote、deadline/status、candidate one per accepted decision。备份恢复验证vote/decision/artifact hashes与source/outbox/inbox一致。

## 9. TDD与追踪

1. 发布Community OpenAPI/event/content/proposal/ballot schemas；privacy/unknown contract RED→GREEN。
2. Domain RED覆盖membership/contribution/proposal/ballot/decision状态、version/hash/quorum/tie。
3. Application RED覆盖eligibility/conflict/reviews/moderation/appeal、vote snapshot/concurrency、candidate非ACTIVE、receipt/fault。
4. Memory GREEN；PUBLIC feature仍off。
5. 真PG18 RLS/secret ballot/unique/deferred quorum/concurrency与rule publisher contract E2E。

| REQ | DESIGN | TEST | CODE | 状态 |
| --- | --- | --- | --- | --- |
| `REQ-COMMUNITY-001` | DES-COMMUNITY-001 · §2/3 | `TEST-APP-COMMUNITY-001` | planned | design |
| `REQ-GOV-001` | DES-GOV-001 · §4/5 | `TEST-PROP-GOV-BALLOT-001`, `TEST-APP-GOV-001` | planned | design |
| `REQ-GOV-002` | DES-GOV-002 · §5 | `TEST-APP-RULE-CANDIDATE-001` | planned | design |
| `REQ-COMMUNITY-002` | DES-COMMUNITY-002 · §6/7 | `TEST-AUTH-COMMUNITY-001`, `TEST-SEC-COMMUNITY-001` | planned | design |
| `REQ-COMMUNITY-003` | DES-COMMUNITY-003 · §8 | `TEST-DB-COMMUNITY-RLS-001` | planned | design |

有效RED后标red；相同断言/真实依赖GREEN后标green。真实社区公开另需启用审批。
