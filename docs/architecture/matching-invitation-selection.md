# MatchingAttempt、MatchRun、业务 Invitation 与 Selection

> 状态：首个交易入口中 Matching & Policy Context 的权威详细设计；独立OpenAPI、事件与五个领域JSON契约、framework-neutral domain、Memory application/UoW及CompleteSelection内存组合协议已通过相同semantic gates；PostgreSQL/RLS/HTTP与CompleteSelection生产绑定仍未实现。
> 适用范围：复合规则发布、候选输入冻结、确定性匹配、业务邀请、候选响应、需求方选择、无匹配关闭，以及唯一 `CompleteSelection` 跨 Context 原子事务。
> 前置依赖：[目标平台领域模型与状态协议](/architecture/platform-domain-model.md)、[匹配、预算与决策](/architecture/matching-and-budget.md)、[Creator Profile](/architecture/creator-profile.md)、[Demand](/architecture/demand-lifecycle.md)与[ADR-0001](/decisions/0001-platform-scope-and-delivery.md)。

## 1. 结果、非目标与事实所有权

本切片把一个已通过验证、资金保障且处于 `MATCHING` 的 exact DemandVersion 变成可审计的人工选择过程：

1. 从 `MatchingRequested` 创建新的 `MatchingAttempt`；
2. 以一个复合规则包和当时可用的 ProfileVersion 集合运行确定性 MatchRun；
3. 对每个输入候选保存完整的 eligible/excluded 结果及原因，不隐藏落选者；
4. 只允许基于 eligible candidate 创建接收者相关的业务 Invitation；
5. 只允许 exact受邀 Creator 接受或拒绝；
6. 只允许绑定exact Selection的ACTIVE `CANDIDATE_SELECTOR` assignment从已接受邀请中人工选择，或明确关闭无选择；
7. 成功选择通过唯一跨 Context 原子事务创建 Project/Agreement shell并推进 Demand。

Matching & Policy Context 拥有 `MatchingRuleBundle`、`MatchingAttempt`、`MatchRun`、`MatchRunInput`、`MatchCandidate`、业务 `Invitation`、`InvitationResponse` 与 `Selection`。它不拥有 Demand、Profile、User、Organization、Funding、Project 或 Agreement。

本页的 `Invitation` 是交易邀请，不是 IAM `AccessInvitation`。它不授予登录、Membership或角色，也不携带匿名能力token；接收者必须先有 ACTIVE User/Session/CREATOR grant，再以 exact relationship 读取。通知只告知门户中有邀请，不是邀请事实来源。

首版不使用大模型、向量检索、embedding、自动选人、公开人才目录、按受保护属性优化排序、付费竞价或黑箱声誉分。算法缩小并解释候选，最终选择仍属于参与者。

## 2. 复合规则包与发布

每个 MatchRun 固化一个 `MatchingRuleBundle`，至少包含：

| 字段 | 规则 |
| --- | --- |
| `id/semantic_version/status` | 状态 `DRAFT / ACTIVE / SUPERSEDED / RETIRED`；同 selector 同时恰一个 ACTIVE |
| `selector_digest` | 对 jurisdiction、locale、demand type、taxonomy family、engine major 与 effective window 的规范事实计算 |
| `taxonomy_bundle_id` | Demand/Profile codes 的同一兼容 taxonomy |
| `budget_rule_version` | 基线、技能系数、历史中位数、风险率与GREEN/YELLOW/RED阈值 |
| `matching_rule_version` | hard filters、六项权重、归一化、舍入、tie-breaker与邀请上限 |
| `reason_code_version` | 排除、风险、override、decline和close的关闭代码 |
| `explanation_template_version` | 只含结构化模板 ID，不含自由提示或模型调用 |
| `engine_identifier/hash` | `deterministic-matcher-v1` 及经过review的实现/测试向量hash |
| `canonical_manifest_sha256/key_id/signature` | 发布清单、受信签名和review approval证据 |
| `effective_at/effective_until` | UTC半开窗口；运行开始时 `effective_at <= db_now < effective_until` |

规则包只能由认证 SYSTEM workload 经 `PublishMatchingRuleBundle` 发布。发布事务外验证受信签名、exact manifest与review approval，事务内锁 selector、current bundle和发布证据；不能由fixture/migration直接插 ACTIVE规避审查。历史运行永远引用原 bundle，ACTIVE替代不会重算旧结果。

同一 bundle 的所有权重必须是规范有理数且总和精确为1；不使用二进制float作为发布或运行事实。hard-filter代码集合必须与engine声明完全一致，缺项和多项都拒绝。发布包包含固定golden vectors，engine在启动和发布时复算；不一致fail closed。

### 2.1 `matching-rule-release-v1` 关闭清单

首版发布清单的 canonical root 恰包含以下字段，未知字段一律拒绝：

```text
schema_version = 1
canonicalization_version = matching-rule-release-json-v1
bundle_id / semantic_version / selector_digest
jurisdiction_code / locale / demand_type_code / taxonomy_family_code
engine_identifier = deterministic-matcher-v1
engine_major = 1 / engine_artifact_sha256
taxonomy_bundle_id / budget_rule_version / matching_rule_version
reason_code_version / explanation_template_version
hard_filters[]
components[]
invitation_limit
golden_vectors[]
effective_at / effective_until
```

`hard_filters` 恰有规则版本声明的15项，每项为 `{code, ordinal, enabled}`，按 `ordinal` 从1连续且code唯一；disabled项仍在清单中，engine不得因省略而产生第二种hash面。`components` 恰有六项 `{code, ordinal, weight_bps}`，`weight_bps` 是拒绝bool的整数0..10000，合计恰10000；basis point就是发布时的规范有理数表示，运行中转为精确Decimal，不接受JSON float或任意分母。

`golden_vectors` 每项只包含 `{vector_id,input_sha256,expected_result_sha256}`，按vector ID UTF-8 byte序，至少三项且必须覆盖excluded、同分tie和budget override。测试向量正文作为reviewed artifact单独打包，其raw-byte SHA-256进入`engine_artifact_sha256`；清单不能嵌入真实Demand/Profile内容。

`effective_until`可空；非空时必须严格晚于`effective_at`。selector canonical bytes固定为：

```text
matching-selector-json-v1(
  jurisdiction_code, locale, demand_type_code,
  taxonomy_family_code, engine_major
)
```

其JCS UTF-8 SHA-256必须等于`selector_digest`。release manifest自身按RFC 8785 JCS UTF-8计算`canonical_manifest_sha256`；signature envelope不进入manifest bytes，但发布命令payload hash同时绑定manifest digest、签名算法/key ID/signature、review approval ID/version。`signature`、credential和approval正文不进入bundle read DTO、audit或事件。

## 3. 输入获取与冻结

`CreateMatchingAttempt` 消费已验证的 `MatchingRequested` source event，并经 Demand 的窄port读取：

- exact organization/demand/demand_version/content hash；
- exact funding ID及仍为SECURED的资格marker；
- composite rule selector/requirement；
- matching request ID/version/status；
- 数据、地域和候选发现所需的最小结构化筛选事实。

Matching不能查询 Demand 表或根据事件payload恢复完整内容。事件只是通知；port返回值、source event和request必须全链一致。

候选发现是一个绑定 `match_run_id/matching_request_id` 的单次 SYSTEM operation，不是公共搜索API。Profile Context 的固定 `CaptureMatchInputs` port只返回当时满足 ACTIVE Profile + ACTIVE User/CREATOR authority + current PUBLISHED ProfileVersion 的候选，及该 exact版本的 MATCH_INPUT投影。Matching传入由Demand和规则派生的关闭 discovery facts，不能传任意SQL/filter/sort。Profile端保存/审计本次candidate allowlist；随后按 exact list读取，不提供跨任务复用的全局profile dump。

MatchRun在进入 RUNNING 前保存不可变 manifest：

```text
demand_id / demand_version_id / demand_content_sha256
funding_id / matching_request_id
matching_rule_bundle_id / selector_digest / manifest_sha256
candidate_count
ordered (creator_user_id, profile_id, profile_version_id,
         profile_content_sha256, evidence_version_digest)[]
input_canonicalization_version = match-input-manifest-v1
input_set_sha256
captured_at
```

同时保存受限 `MatchRunInput` 事实，以便完整复算。它包含算法真正读取的规范化 Demand和Profile字段，但不含contact、Session、provider token、evidence locator、raw文件、review note或支付对象。该表比普通candidate结果权限更窄；需求方、创作者、运营列表和通知都不能读。仅存ID/hash而未保存算法值不算“完整输入快照”。

候选集合为空也是有效、可复算输入，不得制造占位Creator或Selection。

### 3.1 `match-input-manifest-v1` 与算法值快照

机器契约拆为两个关闭对象，避免普通读模型接触算法私密输入：

1. `match-input-manifest-v1` 保存引用、hash和ordered candidate identity；
2. `match-run-input-v1` 保存engine实际读取的最小规范值。

manifest root恰为：

```text
schema_version / canonicalization_version
attempt_id / run_id / organization_id
demand_id / demand_version_id / demand_content_sha256
funding_id / matching_request_id / matching_request_version
matching_rule_bundle_id / selector_digest / rule_manifest_sha256
ordered_candidates[]
captured_at / candidate_count / input_set_sha256
```

candidate identity恰为 `{creator_user_id,profile_id,profile_version_id,profile_content_sha256,evidence_version_digest}`，按`creator_user_id` UTF-8 byte序；五个字段全部参与hash。`candidate_count == len(ordered_candidates)`，0合法。`captured_at`由数据库事务时间产生，不来自事件或worker。

`match-run-input-v1` root绑定同一attempt/run/demand/rule/input-set hash，并包含一个`demand`对象和按同样顺序的`profiles[]`。允许的算法值只来自15个hard filter和六个component的声明：受控codes、UTC日期、整数minor-unit金额与currency、整数容量、规范boolean、0..4等级和受控evidence buckets。它明确禁止自由正文、contact、Organization label、precise location、private floor数值、conflict对象、证据locator/provider响应和受保护属性。private-floor比较由Profile Context返回 `{within_offered_budget:boolean, evidence_digest}`；Matching永远拿不到floor数值。

为使这个对象可被关闭schema验证，首版算法值字段进一步冻结如下。`demand`恰为
`{problem_type_codes,domain_codes,task_codes,must_have_skills,nice_to_have_skills,start_date,due_date,required_weekly_hours,required_duration_weeks,currency,minimum_amount_minor,maximum_amount_minor,allowed_region_codes,required_language_codes,required_work_mode_code,data_sensitivity_code,ai_use_code,budget_override_code}`；skill requirement恰为`{skill_code,minimum_level}`，等级是拒绝bool的整数0..4。`profiles[]`每项恰为
`{creator_user_id,profile_id,profile_version_id,profile_content_sha256,evidence_version_digest,status,interest_problem_type_codes,interest_domain_codes,interest_task_codes,interest_intensity,prohibited_domain_codes,prohibited_task_codes,skills,available_from,available_weekly_hours,available_duration_weeks,currency,within_offered_budget,private_floor_evidence_digest,allowed_data_sensitivity_codes,ai_use_code,language_codes,work_mode_code,region_code,location_eligible,conflict_of_interest}`；skill fact恰为`{skill_code,proficiency_level,evidence_trust_level,evidence_bucket}`，两个等级同样为整数0..4。所有code set去重并按UTF-8 byte序，profile顺序必须与manifest一致。

`budget_override_code`可为`null`或关闭code，只有已由Demand审核留下的YELLOW override才能非空；Profile的`within_offered_budget/location_eligible/conflict_of_interest`是上游基于私密事实计算的规范boolean，不能由Matching以缺省值补造。`private_floor_evidence_digest`只证明比较版本，必须是SHA-256且不得由摘要命名、事件或错误透露原金额。日期严格为UTC业务日`YYYY-MM-DD`；金额与容量是拒绝bool的非负整数。首版机器文件分别命名`match-input-manifest-v1.schema.json`与`match-run-input-v1.schema.json`，不能用一个可选字段大对象合并两种签名面。

两个对象都使用JCS UTF-8；`input_set_sha256`覆盖完整`match-run-input-v1`以及manifest引用，不只覆盖ID列表。capture port返回后，Matching在写事务内独立复算Profile/Demand/content/rule hashes；缺行、重复creator、顺序漂移、candidate_count或hash不一致一律`MATCH_INPUT_CHANGED`且零run结果写入。

## 4. 聚合和状态

### 4.1 MatchingAttempt

`MatchingAttempt` 是一次人机选择周期的根，保存 `id/organization_id/demand_id/demand_version_id/matching_request_id/attempt_no/status/aggregate_version/current_match_run_id/selection_id/created_at/updated_at`。

- 状态只为 `OPEN / SELECTED / CLOSED_NO_SELECTION / INVALIDATED / CANCELLED`；
- `(demand_id, attempt_no)` 唯一递增；同一 Demand 同时最多一个 OPEN；
- `SELECTED/CLOSED_NO_SELECTION/INVALIDATED/CANCELLED` 终态，不重开；
- DemandVersion、Funding资格或规则selector基线改变会 INVALIDATE整个attempt，而不是在旧attempt里偷偷换输入；
- 单纯worker失败可在同一OPEN attempt中创建新的MatchRun，保留supersedes链。

### 4.2 MatchRun 与 MatchCandidate

`MatchRun` 状态为 `QUEUED / RUNNING / COMPLETED / FAILED / SUPERSEDED / CANCELLED`，保存递增 `run_no`、lease/fencing token、输入manifest、规则包、结果hash、candidate计数与aggregate version。

`MatchCandidate` 对每个输入creator恰一行：

| 字段 | 规则 |
| --- | --- |
| identity | run/attempt/creator/profile/profile_version复合身份唯一 |
| `eligibility` | `ELIGIBLE | EXCLUDED`；不存在第三种“未知但参与排名” |
| `exclusion_reason_codes` | EXCLUDED时至少一项，按规则包固定顺序保存全部命中，不短路 |
| component scores | eligible时六项0..100规范decimal；excluded时为空 |
| `total_score/rank` | eligible时必填；同分按opaque creator ID byte序 |
| evidence | 受控matched code、boolean、bucket与版本引用；不保存私密金额/边界正文 |
| `candidate_result_sha256` | 对关闭结果规范字节复算 |

COMPLETED 后输入、候选、分数、排序和解释不可改。FAILED 不回RUNNING；retry创建新run。旧run被SUPERSEDED后仍可审计，但不能新建Invitation。

### 4.3 业务 Invitation

状态固定 `CREATED / SENT / ACCEPTED / DECLINED / EXPIRED / REVOKED`。每条Invitation绑定：

- exact attempt、COMPLETED non-superseded run与ELIGIBLE candidate；
- creator User/Profile/ProfileVersion及其content hash；
- DemandVersion与资金/规则ID；
- immutable recipient disclosure snapshot ID/hash/schema；
- exact offered budget range/currency、schedule、data/AI rules和关键条件摘要hash；
- `expires_at`、created/sent/responded timestamps；
- aggregate version与创建/发布actor证据。

候选不会看到Creator私密floor、其他候选、rank、score、review note或Demand内部预算依据。offered budget range来自已验证Demand内容，并通过candidate `within_budget=true`；它不是最终Agreement金额。Creator ACCEPT表示确认该披露快照/范围仍可继续讨论，不是签署Agreement或保证交付。

同一 `(matching_attempt_id, creator_user_id)` 最多一个非终态Invitation，即使来自不同run。创建只允许当前non-superseded run的ELIGIBLE行。`expires_at <= database_now`即不可响应；后台尚未写EXPIRED也不能继续。

接受时必须重新验证 exact User/Profile仍ACTIVE、CREATOR authority有效、Invitation所引用 ProfileVersion仍是current PUBLISHED且hash/evidence资格未漂移。发布新ProfileVersion不会把邀请静默切到新内容；旧版本失效则响应409并触发attempt invalidation/re-run。拒绝是安全降权，不受hold阻断；reason只接受关闭code，可选受限note不进入普通投影/事件。

### 4.4 Selection

`Selection` 状态为 `OPEN / SELECTED / CLOSED_NO_SELECTION / CANCELLED`，每个attempt恰至多一个，保存aggregate version、current invite集合hash、chosen invitation可空、decision actor与关闭reason。

`current_invitation_set_sha256` 的规范字节面冻结为
`selection-invitation-set-json-v1`：关闭对象只含 `schema_version=1`、
`canonicalization_version`、`attempt_id`、`run_id` 和按 UTF-8
`invitation_id` 升序排列的 `invitations[]`。每个条目只含
`invitation_id / aggregate_version / status / snapshot_sha256`。只纳入同一
attempt、同一当前 run、已经对选择者可见的
`SENT / ACCEPTED / DECLINED / EXPIRED / REVOKED` Invitation；`CREATED` 不得进入。
按 UTF-8 JSON（key 排序、无空白、禁止 NaN）编码后取 SHA-256。任一成员、状态、
aggregate version 或 snapshot hash 变化都必须在同一事务更新 Selection 的 hash 与
aggregate version，并产生 `SelectionInvitationSetChanged`；混入其他 attempt/run、重复
Invitation ID 或无 Selection 时一律失败关闭。ChooseCreator 与 CompleteSelection 均须在
锁内重算该字节面，不能只相信客户端或缓存的 hash。

第一次Invitation SENT时可在同事务创建OPEN Selection；零合格候选时不创建Selection，attempt直接关闭。ChooseCreator只允许绑定exact organization/demand/selection、当前为ACTIVE且未过期的 `CANDIDATE_SELECTOR` assignment执行，并同时校验assignment ID与aggregate version；Organization级 `DEMAND_OWNER` grant不是隐式后门。选择非当前最高rank accepted candidate是允许的人工决定，但必须提供关闭 `selection_basis_code`；代码不能编码受保护属性或自由评价。

Selection只确认已披露的预算范围、schedule与关键条件；正式金额、知识产权、交付和验收由后续AgreementVersion经双方确认。平台不会把算法top-1自动写为selected。

## 5. 确定性计算协议

首版继承[匹配、预算与决策](/architecture/matching-and-budget.md)的15项硬过滤与六项评分，但把运行语义冻结为 `deterministic-matcher-v1`：

1. 所有set输入先按规范UTF-8 byte序去重排序；重复值在上游schema已拒绝；
2. 日期使用UTC业务日语义；期限比较按半开区间；
3. 金额使用最小货币单位整数；不同currency直接 `CURRENCY_MISMATCH`，不隐式换汇；
4. 分数只用Decimal/rational运算，中间不round；每个component最终`ROUND_HALF_EVEN`到2位，总分基于未舍入component计算后同样保留2位；
5. hard filters全部执行并按规则声明顺序保存；EXCLUDED不计算排名，不能靠高分补偿；
6. eligible按unrounded total降序，再按opaque `creator_user_id` UTF-8 byte序；rank从1连续；输入顺序不影响；
7. 预算健康YELLOW只能在Demand审核阶段留下获准override code；matcher不能现场新增override；RED永不进入run；
8. `BELOW_PRIVATE_FLOOR`只保存boolean/reason，candidate/event/需求方解释不保存或反推floor；
9. explanation由关闭模板和受控facts生成，不读取私密金额、边界正文或自由profile text；输出后递归secret sentinel和schema validation；
10. 完成前复算 `input_set_sha256`、每个candidate hash、ordered result hash与rule golden vector；任一漂移整run FAILED，不发布partial排名。

规则包明确15个hard-filter代码、六个component及权重。新增/删除规则必须发布新engine major或兼容rule version、更新schema/docs/golden vectors/性质测试；不能只改Python常量。

### 5.1 `match-candidate-result-v1`

每个输入creator恰生成一个关闭candidate result：

```text
schema_version = 1
canonicalization_version = match-candidate-result-json-v1
attempt_id / run_id
creator_user_id / profile_id / profile_version_id / profile_content_sha256
eligibility
exclusion_reason_codes[]
components[]
total_score / rank
evidence_facts[]
candidate_result_sha256
```

分数在JSON中使用严格字符串`0.00`..`100.00`，而不是number。eligible时`exclusion_reason_codes=[]`、六个component恰按rule ordinal出现、`total_score`非空、`rank`为正整数；excluded时reason至少一项且按hard-filter ordinal，components为空、total/rank为null。`evidence_facts`只允许 `{code,kind,value,source_version_digest}`；kind关闭为`BOOLEAN | CODE | BUCKET`，value对应bool或受控ASCII code，禁止任意字符串和数值金额。

`candidate_result_sha256`不放进自身签名面；其余全部字段按JCS复算。run的`ordered_result_sha256`再覆盖按input candidate顺序排列的candidate digests、eligible排序/rank与rule/input hashes。属性测试必须随机排列输入、重复执行、改变进程locale/timezone/hash seed，并得到相同bytes；任一使用float、Python对象hash或数据库无ORDER BY都应先形成RED。

## 6. 命令、worker与 process manager

| 命令 | actor | 核心守卫与结果 |
| --- | --- | --- |
| `CreateMatchingAttempt` | SYSTEM consumer | exact MatchingRequested inbox/request/Demand/Funding/rule，且执行时无新增hold；创建OPEN attempt与QUEUED run |
| `StartMatchRun` | SYSTEM worker | claim lease/fencing；capture exact inputs；QUEUED→RUNNING |
| `CompleteMatchRun` | same fenced worker | 全candidate关闭结果/hash/泄漏检查；RUNNING→COMPLETED |
| `FailMatchRun` | same fenced worker | 标准错误码；RUNNING→FAILED；私密错误不持久化 |
| `RetryMatchRun` | assigned reviewer/SYSTEM | attempt仍OPEN且输入基线相同；创建新run并supersede旧run |
| `CreateInvitation` | assigned OPERATIONS_REVIEWER | current COMPLETED run、eligible candidate、披露策略、无open duplicate、hold允许 |
| `PublishInvitation` | reviewer/SYSTEM worker | snapshot/schema/deadline/current资格复核；CREATED→SENT；可原子OpenSelection |
| `RespondInvitationAccept/Decline` | exact CREATOR recipient | Session/authority/target关系、deadline、snapshot hash；写唯一response |
| `Revoke/ExpireInvitation` | reviewer/SYSTEM scheduler | 仅未响应；安全降权或deadline；不受hold阻止 |
| `ChooseCreator` | exact CANDIDATE_SELECTOR assignment | assignment ID/version/assignee/resource/expiry、Selection ETag、accepted target、funding/Demand/attempt/current rule、hold；记录选择意图receipt |
| `CompleteSelection` | SYSTEM coordinator + original selector assignment | 重验同一assignment ID/version仍ACTIVE且未过期；唯一跨Context原子事务；创建Project/Agreement并推进三Context |
| `CloseSelectionWithoutChoice` | owner/reviewer | 全invite终态或明确撤回；Selection与attempt关闭 |
| `Invalidate/CancelAttempt` | reviewer/TRUST/SYSTEM | 输入/资金/hold失效；原子撤回open invitation、取消selection/run |

Worker领取使用 `FOR UPDATE SKIP LOCKED`、数据库时钟、lease token和递增fencing generation。完成/失败UPDATE必须同时匹配run ID、RUNNING、worker ID、lease token、generation且`lease_until > db_now`；过期worker不能写结果。retry不复活旧run。

Source event先写durable inbox；同 `(consumer, source_event_id)` 一次转换。处理过程发生COMMIT ack loss时按inbox + target aggregate/receipt重建，不能重复attempt_no/run_no/Invitation/Project。

## 7. 授权、SafetyHold 与非披露

角色不是全表权限：

- creator response：ACTIVE User/Session/Family + account CREATOR grant + invitation exact recipient/profile关系；
- candidate-selector select/close：ACTIVE User/Session + exact resource assignment ID/version/assignee/organization/demand/selection/expiry；Organization级 `DEMAND_OWNER` role不授予选择权；
- reviewer commands：IAM平台职责 + ACTIVE `MatchingReviewAssignment` exact attempt/run/purpose/expiry/conflict attestation；
- SYSTEM：operation-scoped workload credential + exact source event/job/attempt/run；
- no request uses session `active_organization`; organization来自resource并与路径相等。

`CreateInvitation`、`PublishInvitation`、`RespondInvitationAccept`、`ChooseCreator/CompleteSelection`都会增加或确认交易可见性，要求事务外版本化SafetyHold。hold绑定action、actor/original actor、organization、attempt/run/candidate/invitation/selection、各prospective aggregate version、Demand/Profile/input/result/snapshot hash及policy version。锁内任一权威或hash漂移则回滚并出事务重评。BLOCK 403、unavailable 503、零业务写。

Decline/Revoke/Expire/CloseWithoutChoice/Invalidate/Cancel属于安全降权，不被hold阻止。未知ID、跨组织、非recipient、excluded candidate、无assignment和无owner关系对普通调用统一404；已证明关系后才暴露409/412/422。

## 8. API、幂等与并发

首版公开/受控路由：

```text
GET  /v1/me/matching-invitations
GET  /v1/me/matching-invitations/{invitation_id}
POST /v1/me/matching-invitations/{invitation_id}/accept
POST /v1/me/matching-invitations/{invitation_id}/decline

GET  /v1/organizations/{organization_id}/demands/{demand_id}/matching-attempts
GET  /v1/organizations/{organization_id}/matching-attempts/{attempt_id}/selection
POST /v1/organizations/{organization_id}/selections/{selection_id}/choose
POST /v1/organizations/{organization_id}/selections/{selection_id}/close

POST /v1/operations/match-runs/{match_run_id}/invitations
POST /v1/operations/matching-invitations/{invitation_id}/publish
POST /v1/operations/matching-attempts/{attempt_id}/invalidate
```

Worker/process commands无公共route。候选列表对需求方只显示已获准的recipient projection；不得暴露excluded名单、全排名、score或“某人底线太高”。

### 8.1 首版关闭HTTP对象

公开写请求不携带actor、User、Organization role、Session、score、rank、private floor或任意内容快照。首版对象固定为：

| operation | request body | 成功响应 |
| --- | --- | --- |
| accept invitation | `{snapshot_sha256}` | invitation recipient DTO + strong ETag |
| decline invitation | `{snapshot_sha256,reason_code,note?}` | recipient DTO + ETag；note最大500 UTF-8 bytes、NFC、控制字符禁止且永不进入事件 |
| choose | `{invitation_id,selection_basis_code,current_invitation_set_sha256}` | Selection intent DTO，可能处于`OPEN`直到内部complete |
| close | `{reason_code,current_invitation_set_sha256}` | CLOSED_NO_SELECTION DTO |
| create invitation | `{match_run_id,creator_user_id,expires_at}` | reviewer invitation DTO |
| publish invitation | `{snapshot_sha256}` | SENT reviewer DTO |
| invalidate attempt | `{reason_code,input_baseline_sha256}` | terminal attempt DTO |

所有mutation body为`additionalProperties:false`；required字符串按UTF-8 byte上限和NFC检查，bool不能冒充整数。写成功DTO只包含目标ID/status/aggregate_version/updated_at和该recipient allowlist，绝不把review DTO复用于Creator/owner。

read列表使用稳定keyset cursor：creator invitations按`(updated_at DESC,id DESC)`；attempts按`(attempt_no DESC,id DESC)`。cursor HMAC绑定operation、actor、organization可空、filters、sort、limit、schema和key ID，TTL最多15分钟。Selection detail不接受include/fields/sort参数。

### 8.2 `invitation-disclosure-v1`

SENT前冻结的recipient snapshot恰包含：

```text
schema_version / canonicalization_version
invitation_id / attempt_id / demand_id / demand_version_id
profile_id / profile_version_id
organization_preview {organization_id,display_label}
opportunity {title,problem_summary,deliverable_summaries[],acceptance_summaries[]}
offer {currency,minimum_amount_minor,maximum_amount_minor,schedule_code,duration_weeks}
constraints {region_codes[],language_codes[],data_sensitivity_code,ai_use_code}
expires_at / demand_content_sha256 / profile_content_sha256
snapshot_sha256
```

金额是Demand Owner明确愿意披露的offered range；`minimum<=maximum`、同一currency，不能由private floor生成。summary逐项最多500 UTF-8 bytes、总snapshot canonical bytes最多64 KiB，禁止contact、链接、HTML和文件locator。`profile_id/version/hash`只用于recipient确认自己被采用的版本，不附任何Profile正文。snapshot hash覆盖除自身外全部字段；Publish与response均constant-time复算。

所有外部写用Idempotency-Key和目标根If-Match；create子实体还比较父根ETag。与IAM、Profile、Demand统一，strong ETag及If-Match规范文本固定为`"v{aggregate_version}"`，不得发布Matching独有的无`v`格式。receipt keyed identity/payload HMAC遵循平台通用协议，覆盖method/path/organization/target/parent version/body/snapshot hash。raw key、content、score input、decline note、Session secret不持久。

同主体新ACTIVE Session可重放completed safe response；same key/different payload 409。事务内root/child/response/audit/outbox原子，稳定checkpoint逐写覆盖。COMMIT_SENT断线丢弃连接，以新连接精确读取receipt和全部相关aggregate版本；partial/corrupt/IN_PROGRESS fail closed 503。

### 8.3 v1 command receipt、replay 与safe response

每条receipt identity固定保存`command_version=1`、`canonicalization_version=matching-command-json-v1`、`identity_key_id`、`payload_hash_key_id`、principal kind/ID、organization、operation、keyed identity与payload hash；raw Idempotency-Key不保存。identity HMAC绑定canonicalization/command version、principal kind/ID、organization、operation与raw key。payload HMAC的规范JSON根对象关闭为`method,canonical_path,organization_id,target,if_match,command_schema_version,body`：`target`固定kind/ID及可空parent kind/ID，`if_match`为目标或父根version，body是关闭command body。自由note、lease token等必须参与瞬时payload HMAC以区分不同请求，但其原文不能进入receipt、audit、event或safe response。

receipt行本身也是关闭对象。先校验完整shape、version、key IDs、identity binding与字段类型；任一缺失、额外、未知version/key、错identity、非`COMPLETED`、损坏safe response或recovery marker均503。只有完整合法且identity相同的receipt出现不同payload hash时返回`IDEMPOTENCY_KEY_REUSED` 409。

每次调用先执行principal preflight：USER必须是同actor的ACTIVE User与新调用的ACTIVE Session/Family；SYSTEM必须是同workload principal与ACTIVE credential。命中completed receipt后只验证该preflight、receipt和durable recovery facts，不再要求原业务grant、Profile current、review assignment、owner relationship或SafetyHold仍存在；miss才执行完整业务authority与hold。这保证合法完成结果可由同主体的新ACTIVE Session恢复，同时不会绕过当前身份认证。

safe response关闭为`schema_version=1,response_schema,http_status,etag,body`；首版application schema identity固定为`MatchingCommandResult`，body只含目标ID/status/version/updated_at/event types，strong ETag必须与durable target version精确一致。replay必须用同一validator校验wrapper和body，再由durable facts重建application result。audit关闭保存`schema_version,operation,command_version,actor_kind,actor_id,original_actor_id,organization_id,target_id,target_status,aggregate_version,result_code,event_types,occurred_at,correlation_id,causation_id,trace_id`；不保存body、authority正文、自由note或秘密。

Matching Context锁序：source inbox/job → attempt → current run → candidates按creator ID → invitation按ID → selection → receipt。creator response先按IAM authority固定顺序，再进入该序；ChooseCreator先完成外部receipt/selection intent，内部CompleteSelection按 §11独立跨Context顺序。DB partial unique/composite FK是最终防线，原始SQL错误不出wire。

首版业务错误集合：`INVALID_REQUEST`(400)；`AUTHENTICATION_REQUIRED/SESSION_EXPIRED`(401)；`ACCESS_DENIED/SAFETY_HOLD_BLOCKED`(403)；`RESOURCE_NOT_FOUND`(404)；`INVALID_STATE_TRANSITION/IDEMPOTENCY_KEY_REUSED/MATCH_INPUT_CHANGED/MATCH_RULE_BUNDLE_CHANGED/FUNDING_FACT_CHANGED/INVITATION_ALREADY_EXISTS`(409)；`PRECONDITION_FAILED`(412)；`SELECTION_NOT_READY/POLICY_ACCEPTANCE_REQUIRED`(422)；`POLICY_CONFIGURATION_UNAVAILABLE/SERVICE_UNAVAILABLE`(503)。零候选是可复算的成功结果并关闭attempt，不作为错误；operation在OpenAPI逐项列subset，不能让repository发明新code。

## 9. 接收者投影与隐私

| 投影 | 接收者 | 允许字段 |
| --- | --- | --- |
| `REVIEW_RUN` | exact assigned reviewer | run状态、eligible/excluded计数、eligible安全摘要、受控reason/evidence；无私密profile值 |
| `CANDIDATE_SELECTOR_SELECTION` | exact ACTIVE assignment | 仅已获准/已邀请candidate卡、结构化匹配解释、budget-compatible boolean、invitation/response状态；无rank/score/floor/边界/其他私密项 |
| `CREATOR_INVITATION` | exact recipient | immutable opportunity snapshot、offered range、必要schedule/scope/criteria/data/AI规则、自己的response；无其他candidate或内部review |
| `AUDIT_RECOMPUTE` | exact time-bound case assignment | 完整run input/result，字段级审计；不是运营默认视图 |

Invitation snapshot在SENT前冻结并带schema/hash；旧快照不会因Demand/Profile字段变更扩张。公开/anonymous query不存在。所有普通响应no-store、strong ETag、trace ID；固定keyset cursor绑定actor/organization/filters/sort/schema/key IDs。

递归隐私守卫禁止在DTO、事件、audit、receipt、日志、trace、metric、exception、notification、dead letter和shared cache中出现：Creator私密floor/边界/conflict、完整Profile或Demand content、excluded candidate身份、原始分数输入、review/decline自由note、contact、Session/CSRF、idempotency key、evidence/provider locator。Creator可见的offered amount不是私密floor，仍不进入通知正文。

## 10. 事件与审计

事件关闭为：

- `MatchingAttemptOpened(attempt_id,demand_id,demand_version_id,attempt_no,status)`；
- `MatchRunQueued/Started/Completed/Failed/Superseded` 的run/attempt/rule/input/result hash与计数；
- `InvitationCreated/Sent/Accepted/Declined/Revoked/Expired` 的invitation/attempt/creator/profile-version/snapshot hash/status/deadline；
- `SelectionOpened/InvitationSetChanged/Made/ClosedWithoutChoice/Cancelled` 的selection/attempt/chosen invitation可空/status；
- `SelectionIntentRecorded` 的selection/attempt、仍为OPEN的status、current invitation set hash、chosen invitation与关闭selection basis；它是外部Choose receipt完成后供内部coordinator消费的durable trigger，不表示Selection已经SELECTED；
- `MatchingAttemptSelected/ClosedWithoutSelection/Invalidated/Cancelled` 的最小状态事实。

事件不携带profile/demand正文、金额、score、rank、filter reasons、自由解释或note。需要详情的下游通过exact authorized port读取。每个aggregate事件有独立event ID和version；相同business transaction共享correlation/causation/original actor。

### 10.1 v1事件envelope与关闭payload

事件统一使用平台envelope：`event_id,event_type,schema_version=1,occurred_at,aggregate_type,aggregate_id,aggregate_version,actor_kind,actor_id,original_actor_id,organization_id,correlation_id,causation_id,trace_id,payload`，`additionalProperties:false`。各payload只允许：

- Attempt：`attempt_id,demand_id,demand_version_id,matching_request_id,attempt_no,status`，invalidated/cancelled另有关闭`reason_code`；
- Run queued/started：`run_id,attempt_id,run_no,rule_bundle_id,input_set_sha256,status`；completed增加`candidate_count,eligible_count,excluded_count,ordered_result_sha256`；failed只增加稳定`failure_code`；superseded增加`successor_run_id`；
- Invitation：`invitation_id,attempt_id,run_id,creator_user_id,profile_version_id,snapshot_sha256,status,expires_at`，终态增加稳定`reason_code`可空；
- Selection：`selection_id,attempt_id,status,current_invitation_set_sha256,chosen_invitation_id`可空、`selection_basis_code/reason_code`按事件类型可空；
- Selection intent：沿用固定Selection shape，但严格要求`status=OPEN`、`chosen_invitation_id`与`selection_basis_code`非空、`reason_code=null`；只有后续§11同事务成功才发布`SelectionMade(status=SELECTED)`；
- Attempt selected/closed：在Attempt基础上增加`selection_id`及chosen invitation可空。

事件schema用conditionals要求不适用字段为null或不存在（选择一种并全schema一致；首版采用显式null以保持固定shape），不能由serializer按Python值省略产生多种签名面。`InvitationSent`也不包含offered金额或organization label；Notification consumer只以ID调用recipient-scoped intent port。

Audit记录算法规则/input/result hash、命令actor/assignment、目标、结果、关闭reason/override code和Selection与top eligible是否一致的boolean；不保存受保护属性、自由偏好或私密匹配输入。

## 11. CompleteSelection 原子协议

外部 `ChooseCreator` 先以exact `CANDIDATE_SELECTOR` assignment建立完成的选择意图和receipt；receipt与hold binding都冻结assignment ID/version及authority marker。内部协调器携带其 `command_id/original_actor_id/correlation_id`，且不能用 `DEMAND_OWNER` grant代替该资源级assignment。同一数据库中的首版原子事务严格执行：

1. 验证SYSTEM coordinator credential、exact外部completed receipt及其同事务`SelectionIntentRecorded`，预分配project/agreement/event IDs；
2. 按assignment ID锁并重验exact `CANDIDATE_SELECTOR` 当前事实：version、assignee、organization、demand、selection、ACTIVE状态与数据库时钟expiry均须匹配；缺失、撤销、过期、漂移或仅有DEMAND_OWNER grant一律拒绝；
3. 锁 `Selection`，要求OPEN、chosen Invitation已ACCEPTED、selection expected version一致；
4. 锁 `MatchingAttempt`，要求OPEN且selection属于该attempt；Invitation因已是不可逆ACCEPTED并有复合FK，不在此逆序补锁；
5. 通过Demand公开repository锁 `Demand`，要求MATCHING且 exact demand version/matching request/attempt/funding仍一致；
6. 事务内再次验证hold结果绑定的所有版本/hash及selector assignment未漂移；
7. Matching只写 Selection→SELECTED、Attempt→SELECTED及各自事件；Selection结果、内部事件与审计均携带selector assignment ID/version；
8. Project & Agreement只以 `selection_id` 唯一创建PENDING_AGREEMENT Project和唯一Agreement根及各自事件；
9. Demand只写MATCHED及DemandMatched；
10. 写一个跨Context审计关联和各Context outbox，完成外部receipt response；
11. 一次COMMIT；任一checkpoint/constraint/serialization failure全部回滚。

并发相同/不同key最多创建一个Project。COMMIT outcome unknown以exact receipt + Selection/Attempt/Demand/Project/Agreement唯一事实全链裁决；禁止看到Project就猜测其他Context也成功。通知、搜索与分析不在此事务中。

若未来拆库，该协议必须由新ADR改成reservation/saga并保留selection_id唯一与补偿；当前代码不能预先写半套异步事务。

## 12. PostgreSQL 与RLS义务

独立 `matching` schema至少包含rule bundles/current selectors、attempts、runs、run inputs、candidates、invitations/responses、selections、assignments、job leases、command receipts与source inbox引用。

关键约束：同Demand一个OPEN attempt；attempt内run_no唯一；每个run/input creator恰一candidate；excluded无score/rank且eligible必有；eligible rank唯一；开放attempt/creator Invitation部分唯一；Invitation必须复合FK引用同attempt/run的eligible candidate；response每Invitation唯一；Selection每attempt唯一；SELECTED必须有ACCEPTED Invitation；project selection_id唯一由Project schema保证。

全部表ENABLE+FORCE RLS。creator只见自己的Invitation；candidate selector只凭exact ACTIVE assignment看获准selection projection；reviewer只见exact review assignment；worker只见exact job/run/lease；CompleteSelection coordinator只见exact selector assignment/selection/attempt。线上角色非owner、无BYPASS，PUBLIC无表/函数权限。forged GUC、跨org复合引用、expired assignment/lease、非recipient和直接table scan均拒绝。

受限MatchRunInput可使用列级权限与独立online worker role；任何definer函数固定search_path、静态SQL、session_user/current_user/operation/job精确绑定，PUBLIC无EXECUTE。没有“运营看全部”或通用dynamic query函数。

Migration forward-only、raw-byte digest/review pin、逐文件事务、真实PostgreSQL18和wheel验证。并发测试覆盖attempt/run/Invitation/response/selection/Project唯一性、lease fencing、RLS与commit断线。

## 13. TDD实施顺序

1. 发布matching OpenAPI、event schema、rule manifest/input/candidate/invitation snapshot关闭schema；contract先RED→GREEN。
2. Domain/性质RED覆盖Attempt/Run/Invitation/Selection全部转换、终态、expiry equality、候选shape、确定性/排列不变/舍入/tie、私密floor不出结果。
3. Memory application RED覆盖source event、input capture、零候选、worker lease、retry、eligible-only invite、recipient响应、hold drift、人工选择、receipt/rollback/commit unknown。
4. Memory GREEN并用MVP fixed samples做差分；任何差异要明确版本化，不修改历史结果冒充兼容。
5. 先写PostgreSQL/RLS详细页，再用真PG18 RED验证复合FK/partial unique/伪GUC/租约竞争/同候选双邀/双响应/双选择与CompleteSelection每写点回滚，最后forward-only GREEN。
6. 实现HTTP/presenter/composition，跑Demand+Profile+IAM+Matching+Project shell+Outbox真实PG E2E；三个recipient秘密sentinel。
7. 只有全门禁GREEN后才可作为production Match输入；真实启用仍受ADR-0001证据门槛。

### 13.1 第一轮 contract GREEN 与 semantic RED 证据

第一轮严格停在 contract-first RED 边界：

- `platform/contracts/api/matching-v1.openapi.yaml` 独立发布 §8 的11条公开/受控route；worker、process manager与`CompleteSelection`没有公共route。所有mutation body关闭，并机器绑定Idempotency-Key、If-Match、CSRF与逐operation错误subset。
- `matching-v1.schema.json`与`matching-rule-release-v1`、`match-input-manifest-v1`、`match-run-input-v1`、`match-candidate-result-v1`、`invitation-disclosure-v1`五个领域schema均为Draft 2020-12关闭对象。契约门禁覆盖全部20种event type、eligible/excluded条件联合、严格score字符串、零candidate、bool不能冒充整数、未知/私密字段不可表示；`tests.contract.test_matching_contracts`为11 tests、11 pass、0 failure/error/skip。
- production仅新增`desire_platform.matching.domain/application/ports` immutable shapes、关闭dependency ports和稳定`MATCHING_*_BEHAVIOR_NOT_AVAILABLE` default-deny handler/function，不含Memory store、PostgreSQL、HTTP、composition或test-mode分支。
- `tests.matching.test_matching_domain_red`为13 tests：12项semantic failure、1项immutable pass、0 error/skip；覆盖Attempt/Run/Invitation/Selection、deadline equality、eligible/excluded shape、Decimal/string score、排列/tie/hash及private-floor数值不可表示。
- `tests.application.test_matching_commands_red`为19 tests：18项semantic failure、1项immutable pass、0 error/skip；覆盖source inbox/exact Demand链、完整input capture、零候选、lease fencing、retry、eligible-only invite、recipient响应、exact reviewer assignment+duty与owner organization authority、hold drift、人工choose、keyed receipt、13 checkpoints、COMMIT outcome unknown与递归隐私。

这些failure只由窄捕获稳定default-deny sentinel转换而来；ImportError、意外dependency异常、skip和测试环境分支均为0。后续Memory GREEN必须保持相同断言，不得把contract GREEN冒充业务实现。

### 13.2 第二轮 Memory GREEN 与 fixture correction

第二轮先将domain 13 tests原断言不变转为13/13 GREEN，再实现application Memory transaction并将19 tests转为19/19 GREEN。机器contract全量保持59/59 GREEN。实现边界如下：

- domain现在执行Attempt/Run/Invitation/Selection状态机、`expires_at <= database_now`、eligible/excluded关闭联合、Decimal两位score字符串、规范JSON bytes、candidate/result SHA-256、排列不变与opaque ID tie-break；candidate hash排除自身digest，private floor数值不进入任何领域shape。
- application使用显式dependency ports和copy-on-write Memory UoW；先做exact SYSTEM、review assignment+duty、Creator recipient或resource-scoped Candidate Selector assignment，再claim keyed receipt、按§8锁序读取既有aggregate、复核Profile/Demand/input/hold绑定并执行稳定checkpoint。没有缺失pre-state时lazy seed、合成成功DTO或default fixture fallback。Choose的SafetyHold先以已提交snapshot在事务外计算包含selector assignment ID/version/marker的完整version/hash binding；root lock后从工作副本重算同一binding并与外部结果逐字段exact compare，任一漂移以`SERVICE_UNAVAILABLE`回滚receipt claim及全部业务写。
- `MatchingRequested`先经source validator，事务内durable inbox保存`COMPLETED`并绑定唯一attempt；input capture改为锁住run/attempt后以exact attempt/run/matching request调用，零候选仍完成run并关闭attempt而不创建Selection。
- worker完成必须匹配RUNNING、worker、lease token、fencing generation及`lease_until > db_now`；retry保留FAILED run并创建递增successor；Invitation只从current non-superseded COMPLETED run的ELIGIBLE candidate创建，publish/response复核exact snapshot与current Profile authority。
- Choose只保存OPEN Selection intent与completed receipt并发布新增关闭事件`SelectionIntentRecorded`；它不写`SelectionMade`、不推进SELECTED、不创建Project/Agreement、不写Demand。后续§11 coordinator以receipt+intent为durable trigger。
- 每个application outbox envelope在测试中直接经过正式`matching-v1.schema.json`；safe response固定关闭shape。raw key、lease/session/workload secret、decline note、candidate input与private floor数值只可参与瞬时keyed binding或受限事实，不能进入receipt body、event、audit或异常。
- COMMIT ack-loss只有durable commit场景可恢复：新reader同时验证completed receipt safe body、target aggregate及Selection/Attempt/Invitation/Run/selection intent全部marker；缺项、版本/status漂移或IN_PROGRESS均fail closed。

default-deny RED阶段的application arrange没有seeded aggregate且`_Recorder`读取恒为`None`，掩盖了真实实现前提。GREEN前只按设计原义纠正support/arrange；其中三项同时纠正原先从未越过sentinel的无效oracle：

1. source inbox改为断言durable store中恰一条`COMPLETED`及source validator恰调用一次；
2. hold drift真实篡改锁内绑定，断言`SERVICE_UNAVAILABLE`且receipt/audit/outbox与全部业务snapshot零变化，不再同时要求成功OPEN；
3. receipt replay第二次使用同一完整authority/UoW依赖和新调用上下文，读取durable completed receipt，仅跳过允许跳过的业务评估。

另一个RED歧义是Choose要求OPEN intent却没有合法关闭事件：按§10/§11裁决先让contract对`SelectionIntentRecorded`产生1个有效failure，再扩事件schema转GREEN；未用`SelectionMade`冒充提前完成。19个test method和其余业务边界未删除或放宽。

### 13.3 第二轮 receipt/audit 安全 RED → GREEN

主实现审查后追加7个独立security methods，先固定为7 semantic failures、0 errors、0 skips：分别钉死receipt关闭version/key metadata、method/path/target/If-Match/schema payload、corrupt 503与唯一payload conflict 409、同主体新ACTIVE Session的principal-only replay、inactive Session拒绝、完整关闭audit、safe response schema/status/ETag及六类corruption fail closed。随后按§8.3实现，7/7 GREEN；原domain 13与application 19断言仍GREEN。

跨Context审查同时发现Matching最初使用无`v`的ETag格式。设计与contract oracle先改为平台统一`"vN"`，在旧OpenAPI上取得`test_openapi_mutations_are_closed_keyed_etagged_and_csrf_bound`精确1 failure、0 errors/skips；再同步If-Match、四类response ETag、safe receipt与durable replay binding，Matching contract 11/11及全量contract 59/59 GREEN。

最终Memory门禁证据：Matching domain/application/security合计39 tests、39 pass；全量机器contract 59 tests、59 pass；非PostgreSQL稳定回归按application、authentication、authority lifecycle、authorization、Creator Profile、Demand、HTTP、policy/consent及read-model分组共293 tests、293 pass。以上运行均为0 failure、0 error、0 skip；本轮没有新增PostgreSQL schema/migration/RLS、HTTP或composition，也没有修改IAM、Profile或Demand production实现。

## 14. REQ → DESIGN → TEST → CODE

| REQ | DESIGN | 验收 TEST | CODE | 状态 |
| --- | --- | --- | --- | --- |
| `REQ-MATCH-001` | DES-MATCH-001 · §2/3 | `TEST-CONTRACT-MATCH-RULE-001`, `TEST-APP-MATCH-INPUT-001` | `platform/contracts/domain/matching-rule-release-v1.schema.json`; `match-input-manifest-v1.schema.json`; `match-run-input-v1.schema.json`; `platform/src/desire_platform/matching/application/handlers.py` | memory-green |
| `REQ-MATCH-002` | DES-MATCH-002 · §4/5 | `TEST-PROP-MATCH-DETERMINISM-001`, `TEST-UNIT-MATCH-001` | `platform/src/desire_platform/matching/domain/model.py`; `platform/tests/matching/test_matching_domain_red.py` | memory-green |
| `REQ-MATCH-003` | DES-MATCH-003 · §4/6 | `TEST-APP-MATCH-INVITATION-001` | `platform/src/desire_platform/matching/application/handlers.py`; `platform/tests/application/test_matching_commands_red.py` | memory-green |
| `REQ-MATCH-004` | DES-MATCH-004 · §4/6/11 | `TEST-APP-MATCH-SELECTION-001`, `TEST-E2E-COMPLETE-SELECTION-001` | Memory intent GREEN；CompleteSelection E2E planned | partial-green |
| `REQ-MATCH-005` | DES-MATCH-005 · §7/9 | `TEST-AUTH-MATCH-001`, `TEST-SEC-MATCH-001` | `platform/src/desire_platform/matching/ports/commands.py`; `platform/src/desire_platform/matching/application/handlers.py` | memory-green |
| `REQ-MATCH-006` | DES-MATCH-006 · §6/8 | `TEST-APP-MATCH-RECEIPT-001`, `TEST-DB-MATCH-CONCURRENCY-001` | Memory receipt/rollback/unknown GREEN；DB planned | partial-green |
| `REQ-MATCH-007` | DES-MATCH-007 · §10 | `TEST-EVENT-MATCH-001` | `platform/contracts/events/matching-v1.schema.json`; runtime schema validator | green |
| `REQ-MATCH-008` | DES-MATCH-008 · §12 | `TEST-DB-MATCH-RLS-001` | planned | design |
| `REQ-MATCH-009` | DES-MATCH-009 · §11 | `TEST-DB-COMPLETE-SELECTION-001` | planned | design |

只有有效RED后状态才改为red；相同断言、适用回归和真实依赖GREEN后才改为green并回填实现路径。
