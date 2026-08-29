# IAM 身份绑定、账户恢复与关闭

> 状态：IAM 后续权威设计；机器契约与可执行 RED 尚未提交，所有 linking/recovery/closure 入口默认关闭。
> 适用范围：OIDC identity新增/移除、verified contact变更、失去provider后的账户恢复、主体合并禁止规则、账户关闭及Session/authority后果。
> 前置设计：[身份、租户、政策同意与会话](/architecture/identity-tenancy-consent.md)、[数据权利与清除](/architecture/data-rights-retention-and-erasure.md)和[Trust/Safety](/architecture/trust-safety-dispute-review.md)。

## 1. 安全目标与非目标

平台必须允许合法User在provider迁移、失去设备或contact变更后恢复访问，同时不能让email所有权、客服判断、provider display name或当前浏览器cookie单独成为账号接管依据。

硬约束：

- `(provider_code,issuer,subject)` 是ExternalIdentity唯一身份；email/phone永远不是自动合并键；
- linking不改变User ID、role、Membership、Profile、Project或交易party；
- recovery不创建新业务权限，也不恢复已撤销grant/Consent/Session；
- 两个既有User不能自动/人工“合并”成一个User；冲突进入受控case，必要时保留两个主体并由业务Context纠正关系；
- 支持人员无权直接UPDATE User、ExternalIdentity、ContactPoint或Session；
- 关闭账户不是物理清空所有交易证据，删除/保留由Data Rights流程执行。

首版不提供本地密码、security question、短信单因子、社交图证明、AI人脸判断、任意证件自动审核或跨jurisdiction通用KYC。

## 2. 聚合与状态

### 2.1 IdentityLinkRequest

状态：`CREATED / PROVIDER_PENDING / PROOF_VERIFIED / COOLDOWN / APPLIED / REJECTED / EXPIRED / CANCELLED`。绑定：

- exact authenticated User/Session/family与recent STEP_UP AuthTransaction；
- prospective provider/issuer/subject的sealed claim digest；
- provider transaction/browser binding/nonce/PKCE；
- current identity set hash、contact set hash、User aggregate version；
- risk policy/version、SafetyHold result与cooldown deadline；
- receipt/audit/outbox和通知intent。

provider callback只完成一次性proof，不直接insert ExternalIdentity。进入COOLDOWN后向所有既有安全通知渠道发送“新增身份”提醒；到期后单独`ApplyIdentityLink`命令重新验证User/Session/identity set/risk/hold。高风险policy可要求独立运营review，但reviewer只看最小proof摘要。

### 2.2 IdentityUnlinkRequest

只有当应用后仍至少一个满足当前登录政策的ACTIVE ExternalIdentity，或已经完成新的recovery credential enrollment，才能移除。不能移除当前Session所属identity而不先STEP_UP到另一identity。状态与link相同；cooldown期间任何既有identity可取消。

unlink把identity标为`UNLINKED`并保留provider subject keyed tombstone/历史User binding，防止它被静默绑定到另一个User；不删除provider原始subject的sealed reference直到retention允许。所有Session family原子撤销，User必须重新登录。

### 2.3 ContactChangeRequest

contact不是身份，但用于通知/恢复辅助。状态`CREATED / CHALLENGE_SENT / VERIFIED / COOLDOWN / APPLIED / REVOKED / EXPIRED / CANCELLED`。新contact用用途隔离challenge、attempt限制和provider回执验证；旧contact收到变更通知。APPLIED时新行ACTIVE、旧行REVOKED（除非政策允许多个用途分离contact），不会改ExternalIdentity。

### 2.4 AccountRecoveryCase

状态：

```text
OPEN -> EVIDENCE_PENDING -> REVIEW_PENDING -> APPROVED_COOLDOWN
     -> RECOVERY_READY -> COMPLETED
     -> REJECTED / EXPIRED / CANCELLED
```

case使用公开随机case capability进入，但capability只定位case，不证明User。内部保存candidate User keyed digest、proof manifest和最小风险facts；公开错误不确认contact/provider/User是否存在。

### 2.5 AccountClosureRequest

状态`CREATED / IMPACT_REVIEW / COOLDOWN / READY / APPLIED / BLOCKED_OBLIGATION / CANCELLED / EXPIRED`。关闭请求先创建Data Rights任务和交易影响manifest，列出开放Project/Funding/Dispute、唯一ORG_ADMIN责任、legal hold等安全code；不向普通DTO披露他人或case细节。

APPLIED时User→CLOSED、全部Session family撤销、ExternalIdentity登录禁用、未完成AccessInvitation/业务Invitation按各Context协议撤销、所有active roles/Memberships按职责转移/最后管理员守卫处理、processing restriction生效。付款退款、Agreement、争议与删除异步处理；不能为求“立即删除”制造孤儿或绕开义务。

## 3. Proof与风险政策

`IdentityRecoveryPolicyBundle`按jurisdiction/risk tier/account authority发布，列出允许proof组合、cooldown、review duty、通知、attempt/rate、provider trust和恢复后限制。当前规则包/manifest经签名与双人批准，不能在case中临时降级。

proof关闭类型可包括：

- 仍ACTIVE的另一个ExternalIdentity + recent provider authentication；
- 预先enrolled硬件/平台passkey的challenge proof；
- 预先生成并hashed存储的一次性recovery code；
- 已验证contact challenge，仅作为组合因素，不单独足够；
- 已知Project/Agreement等relationship challenge的非秘密code，仅作为辅助，不询问可从公开资料猜到的正文；
- 人工identity evidence，经独立review且短期sealed retention。

每个proof保存`proof_type,verifier_version,evidence_digest,verified_at,expires_at,result,risk_signal_codes`，不保存credential/raw provider response/证件正文。组合必须满足policy表达式和factor independence；同一email经两个渠道不能算两个独立factor。

禁止：邮箱收到link等于User、provider返回相同email就merge、客服查看profile后口头通过、只验证身份证照片、只依赖旧设备cookie、让请求者选择目标User ID。

## 4. 恢复协议

1. `BeginAccountRecovery` 接受provider/contact的opaque recovery hint，经速率限制后总返回相同safe case响应；
2. 服务端在受限resolver中生成candidate set，0/1/多候选都不对外区分；
3. 按policy逐项建立独立challenge transaction，raw capability/response只在对应port；
4. proof达到阈值后进入独立review或APPROVED_COOLDOWN；所有既有contact/identity发送安全通知；
5. cooldown期间既有ACTIVE Session/identity可取消并触发Trust review；
6. 到期后`CreateRecoverySession`事务重新锁User、identities、contacts、case与policy，确认无drift/hold；
7. 创建特殊`RECOVERY` Session，短absolute TTL、强制STEP_UP/enroll新identity，不能直接执行付款、Agreement确认、角色管理、data export等高风险命令；
8. 完成新identity绑定后撤销User全部其他Session family和未使用recovery material，case→COMPLETED；
9. 恢复后风险窗口内高风险动作需要fresh MFA/人工复核。

recovery Session在HTTP/Session持久事实有`creation_reason=ACCOUNT_RECOVERY`、case ID和restriction policy version；raw handle/CSRF仍不持久。普通handler从IAM authority projection看见restriction codes，不能靠UI隐藏按钮。

任何版本/hash/candidate/proof/policy drift都使当前attempt回滚并在事务外重评。SafetyHold BLOCK/UNAVAILABLE分别403/503；取消、Session撤销和账户安全降权不被hold阻断。

## 5. Linking协议

只有ACTIVE User + ACTIVE Session/family + recent STEP_UP可以begin。OIDC authorization明确purpose=`LINK_IDENTITY`、expected_user_id与current identity set hash，并使用独立browser cookie/capability；普通LOGIN callback不能变成link。

callback验证issuer/audience/nonce/PKCE/max-age后：

- identity不存在：写proof transaction，进入cooldown；
- identity已绑定同一User且ACTIVE：幂等safe result，不建重复行；
- identity已绑定其他User或UNLINK tombstone：统一`IDENTITY_LINK_UNAVAILABLE`，零关系写并创建受限security signal；
- provider key/config unavailable：503，不把它说成“身份不存在”。

Apply事务锁User→Session family/Session→current ExternalIdentities按ID→request→provider proof→receipt，重算set hash；insert identity、User version、全部Session revoke、audit/outbox/receipt一次提交。成功响应不含provider subject、claims或新Session秘密；User重新LOGIN。

## 6. 并发、幂等与结果未知

所有外部写使用Idempotency-Key和根If-Match；provider callback以transaction/browser binding CAS，不接受客户端Idempotency-Key替代。receipt payload绑定method/path/purpose/User/case/request/current set hash/policy/expected version和关闭body。

数据库唯一约束保证一个provider identity最多绑定一个User、一个request只能apply一次、一个recovery material只能消费一次。两个User并发link同一identity最多一方成功；失败方统一不可用，不暴露赢家。

COMMIT_SENT断链用新连接读取receipt、request/case状态、ExternalIdentity/User version、Session revocation和outbox全链。无法证明exact complete或absent则`COMMAND_OUTCOME_UNKNOWN`/503；绝不重新执行provider exchange、发送新challenge或创建第二Session。

## 7. API与错误

计划SELF路由：

```text
GET  /v1/me/external-identities
POST /v1/me/external-identities/link-authorizations
GET  /v1/me/external-identities/link-callback
POST /v1/me/external-identities/{identity_id}/unlink
POST /v1/me/contact-change-requests
POST /v1/me/account-closure-requests
GET  /v1/me/account-closure-requests/{request_id}

POST /v1/auth/account-recovery-cases
POST /v1/auth/account-recovery-cases/{case_capability}/proofs
GET  /v1/auth/account-recovery-cases/{case_capability}
POST /v1/auth/account-recovery-cases/{case_capability}/complete
```

公开recovery route统一shape/latency bucket/限速响应，不回显User/identity/contact。SELF identity DTO只显示provider安全label、linked_at、last_used_at bucket、是否current与能否unlink；不返回subject/email claims。

新增wire codes需先改IAM OpenAPI：`IDENTITY_LINK_UNAVAILABLE`(404或409按已证明关系)、`RECOVERY_UNAVAILABLE`(404)、`RECOVERY_PROOF_REQUIRED`(422)、`RECOVERY_COOLDOWN_ACTIVE`(409)、`ACCOUNT_CLOSURE_BLOCKED`(409)。在机器契约发布前handler保持default-deny，不能把内部码塞进现有ErrorResponse。

## 8. PostgreSQL与RLS

IAM扩展表至少包含identity_link_requests、identity_unlink_requests、contact_change_requests、recovery_cases/proofs/materials、account_closure_requests/impact manifests和security notification intents。v0以后只用forward migration。

- 全表ENABLE+FORCE RLS；SELF只见当前User的安全投影；anonymous recovery只经case capability exact definer函数；
- provider callback role只见exact AuthTransaction/request，不可列identity/User；
- recovery reviewer只见assigned case最小proof，不见普通IAM表；
- support/operator无ExternalIdentity subject/contact locator SELECT；
- definer函数固定search_path、静态SQL、session_user/current_user/operation/case全链，PUBLIC无EXECUTE；
- provider subject使用用途隔离keyed digest查唯一，sealed ciphertext/nonce/key ID列无在线普通读取；
- partial unique限制每User/provider active identity、每User开放link/unlink/closure、每material未消费状态；复合FK绑定request/User/provider proof。

真实PG18测试覆盖伪GUC/capability、跨User、同identity双link、同material双消费、cooldown equality、last identity unlink、最后ORG_ADMIN closure、session revoke、receipt竞争和pool reset。

## 9. 事件、审计与隐私

关闭事件：`ExternalIdentityLinked/Unlinked`、`ContactPointChanged`、`AccountRecoveryOpened/Approved/Completed/Rejected/Cancelled`、`AccountClosureRequested/Applied/Blocked`、`UserClosed`。payload仅User/request/case keyed/opaque IDs、provider code、status、policy/reason、timestamps；不含issuer/subject/contact/proof/capability、credential、provider claims或case evidence。

安全通知intent只含recipient User ID、template code和request/case ID；Notification Context在发送时解析当前contact。旧contact通知需要受控sealed delivery task，不能把locator复制进outbox。

Audit记录actor/original actor/duty/action/target/result/policy/proof-type codes；proof/evidence读取产生SensitiveAccessEvent。日志/trace/metrics禁止case capability、provider authorization URL、subject digest、contact、document ref、Session/CSRF和receipt key。

## 10. 与Data Rights和业务Context的关系

- closure先写全局processing restriction，阻止新Profile publish、Demand、Matching、AI和营销；
- 开放Project/Funding/Dispute按各Context转移/关闭/保留协议处理，不能由IAM级联删除；
- User CLOSED后历史交易party用稳定User ID或pseudonymous party ref，不重新绑定另一个User；
- closure APPLIED触发DataSubjectRequest/retention tasks，但legal hold/transaction minimum可导致PARTIAL；
- recovery不会撤销已提交的erasure/restriction watermark，也不能把已关闭User恢复ACTIVE；CLOSED主体必须走独立法律/人工流程，首版不支持reopen。

## 11. TDD追踪

| ID | RED | GREEN门槛 |
| --- | --- | --- |
| TEST-CONTRACT-IAM-RECOVERY-001 | API/event可表达email merge、raw proof/subject/capability | 关闭OpenAPI/event/proof schema |
| TEST-DOMAIN-IAM-RECOVERY-001 | cooldown等号、proof复用、last identity unlink、CLOSED恢复 | domain状态与property tests |
| TEST-APP-IAM-LINK-001 | LOGIN callback越权link、同email merge、跨User枚举 | strict provider fake + Memory UoW |
| TEST-APP-IAM-RECOVERY-001 | 单因素contact接管、reviewer越权、恢复Session无限权 | policy组合/assignment/restriction/hold tests |
| TEST-DB-IAM-RECOVERY-001 | 伪GUC/capability、双link/双consume、RLS绕过 | 真实PostgreSQL 18并发/RLS/fault tests |
| TEST-APP-IAM-CLOSURE-001 | 删除User造成孤儿、last admin、开放资金/争议被忽略 | impact manifest + Data Rights coordination |
| TEST-E2E-IAM-RECOVERY-001 | fake-only成功 | 真实OIDC sandbox/browser/PG/通知/冷却时钟E2E |
| TEST-SEC-IAM-RECOVERY-001 | logs/events含subject/contact/proof/capability | recursive secret sentinel与访问审计 |

实施顺序：司法辖区与provider threat review → OpenAPI/event/proof contract → domain/application RED→Memory GREEN → PostgreSQL/RLS RED→GREEN → provider sandbox/linking browser E2E → recovery/closure/Data Rights fault E2E。任何阶段不得用测试后门、固定allow token、support owner连接或email自动merge求GREEN。

## 12. 当前实施边界

当前IAM实现只有邀请制OIDC登录、Session、权限/Consent和部分生命周期；本页所有新命令、表、provider purpose、错误码、UI与E2E均未实现。生产composition必须保持link/recovery/closure feature gate关闭，直到机器契约、风险政策、真实provider和通知/人工响应能力全部通过门禁。
