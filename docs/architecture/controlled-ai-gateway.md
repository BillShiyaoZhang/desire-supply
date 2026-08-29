# Controlled AI Gateway、模型策略与人工确认

> 状态：Controlled AI Gateway 的权威详细设计；机器契约和可执行 RED 尚未提交，真实模型provider默认关闭。
> 适用范围：ModelPolicy/PromptVersion发布、AIJob输入最小化、provider调用、结构输出、评测、人工确认、prompt injection与隐私。
> 非目标：自动选择、付款、处罚、裁决、协议签署、身份验证或绕过业务Context守卫。

## 1. 权限边界

AI Gateway拥有 `ModelPolicyBundle`、`PromptVersion`、`AIJob`、`AIInputManifest`、`AIOutputArtifact`、`AIEvaluation` 与provider call projection。它不拥有Demand/Profile/Agreement/Trust等业务聚合，也不持有调用这些Context写命令的credential。

每个AI能力必须由一个published `capability_code`定义，例如 `DEMAND_CLARIFICATION_DRAFT`、`EVIDENCE_INDEX_SUGGESTION`、`DELIVERY_SUMMARY_DRAFT`。未发布能力默认拒绝。首版明确禁止：

```text
MATCH_CANDIDATE_RANKING
SELECT_CREATOR
ACCEPT_DELIVERY
RELEASE_OR_REFUND_FUNDS
ISSUE_SAFETY_PENALTY
ISSUE_RULING_OR_APPEAL_DECISION
GRANT_IDENTITY_OR_ROLE
SIGN_OR_ACCEPT_AGREEMENT
```

即使provider返回这些“建议”，关闭output schema也无法表示，application不会dispatch业务命令。人工点击采用后仍创建目标Context正常命令，重新验证actor/ETag/hold/policy，记录AI artifact source；AIJob本身没有authority。

## 2. ModelPolicyBundle 与 PromptVersion

ModelPolicy selector包含capability、jurisdiction/locale、data classification、provider/model family、region和effective window。发布artifact冻结：

- provider/model identifier与允许version range；
- input/output closed JSON Schema及字段classification allowlist；
- prompt template AST、system policy、tool list（首版空或纯读exact port）、max tokens/latency/cost；
- retention/training/region/zero-data-use provider contractual mode；
- required consent/policy/feature flag/human-review role；
- content safety与prompt injection defenses；
- evaluation dataset/version/threshold与known limitations；
- canonical manifest/hash、signing trust与independent approval。

PromptVersion append-only，不能在production UI原地编辑。模板变量typed/escaped，引用closed field paths；不执行任意code/include/network。provider/model/prompt更换发布新bundle，历史job固定旧版本。

发布由认证SYSTEM workload，事务外验证signature/manifest/approval/evaluation，事务内锁selector/current。evaluation未达阈值、provider合同配置缺失或artifact drift都不能ACTIVE。

## 3. AIJob 与输入最小化

状态：`CREATED / INPUT_READY / QUEUED / RUNNING / OUTPUT_READY / ACCEPTED / REJECTED / EXPIRED / FAILED / CANCELLED`。

创建要求当前User/party有业务resource关系、feature flag开启、exact purpose政策/consent有效、resource状态允许，并预分配job/output IDs。`AIInputManifest`只保存：

```text
capability/policy/prompt/provider versions
source resource IDs + aggregate versions + content hashes
field allowlist and per-field classification
redaction/transformation versions
canonical minimized input hash
consent/policy evidence IDs
requested_by/organization/purpose/deadline
```

AI Gateway通过源Context的capability-specific fixed port读取exact allowlist，不接受客户端粘贴完整业务对象或任意field paths。contact、Session/token、私密floor、payment credential、Trust reporter/evidence正文、File binary默认不可用。restricted字段只有policy/consent/provider mode/assignment全部允许时才进入，并有更短retention。

输入内容视为不可信数据。系统指令与数据使用结构分隔/typed serialization；文档中的“忽略规则/调用工具/泄露prompt”只是文本。首版无通用browser/shell/database/tool execution；若未来加tool，每个tool为exact read-only operation、参数closed、结果再做classification，且job capability显式允许。

## 4. Provider调用与结果未知

DB事务内创建job/outbox task并COMMIT；worker以lease/fencing领取后在事务外调用provider。credential来自purpose/environment/provider scoped KMS，repr/log不可泄漏。provider request ID/idempotency key由job+attempt派生；raw prompt/request/response不写普通日志/audit/outbox。

超时/断线/ack unknown不猜成功。若provider支持idempotency/query，按exact job查询；否则标内部 `RESULT_UNKNOWN`、停止自动重复高成本/敏感调用并进入人工reconcile。retry创建新attempt，保持同job/input/policy；输入或policy改变必须新job。

provider raw response先留在短期受限buffer，依次执行size/depth/Unicode、closed output schema、引用/事实边界、content safety、secret echo、prompt leakage与capability-specific validator。失败只保存controlled code/hash并销毁raw；不能把近似JSON/未知字段“修好”后冒充模型输出。

## 5. OutputArtifact 与人工采用

合法输出成为immutable `AIOutputArtifact`：job/input/policy/prompt/model versions、closed content、canonical hash、provider observed metadata安全子集、validation/evaluation versions、created/expires。禁止保存chain-of-thought或隐藏推理；对用户只显示可核验的简短依据/引用。

业务界面明确标识AI draft、来源、限制、过期和需人工确认。`AcceptAIOutput`只把artifact标ACCEPTED并返回可用于目标命令的source reference；它不修改业务resource。目标命令body由User编辑/确认后进入正常closed schema；handler记录source artifact ID/hash但不信任其正确性。

REJECTED/EXPIRED artifact不能采用。source resource/version、policy/consent或hold漂移时采用失败，需新job；不能在旧artifact上换target。

## 6. 安全、隐私、公平与评测

每个capability有离线golden/adversarial suite：schema adherence、事实引用、幻觉、prompt injection、secret echo、语言、偏差、拒绝、延迟/成本。上线用shadow/canary和人工review，threshold/样本/版本持久。评测集使用合成/获准数据，Trust/真实participant正文默认排除。

在线指标只用capability/model/policy version、outcome/error、latency/token/cost bucket和human accept/edit/reject rate；无User/org/resource ID或prompt/output。质量下降、provider policy变化、安全事件或成本异常自动停止新job，不回滚已完成业务。

模型输出不得推断/生成受保护属性或将其用于资格/排序。解释/摘要不能泄露接收者不可见源字段。content filters不能代替业务closed schema/authorization。

provider训练/retention默认禁止；若无法合同保证则该classification能力不可用。用户opt-out/consent withdraw阻止新job并按retention删除可删artifacts，不改写已被人工业务决定引用的最小source证据。

## 7. API、授权与幂等

```text
POST /v1/ai/jobs
GET  /v1/ai/jobs/{job_id}
POST /v1/ai/jobs/{job_id}/accept
POST /v1/ai/jobs/{job_id}/reject
POST /v1/ai/jobs/{job_id}/cancel
POST /v1/operations/ai/model-policies/publish
GET  /v1/operations/ai/evaluations
```

Create body只含capability、source resource ID/version、locale与closed options，不含raw source content/provider/model/prompt。actor来自BFF；resource relationship、policy/consent/hold由server解析。读取只限requester/获准party/assignment。

所有写Idempotency-Key+job If-Match；receipt不存input/output/raw key。provider回调若有则用verified event identity。锁序：authority/source marker→policy selector/bundle→job→attempt→artifact→receipt。provider调用无DB事务。

wire：400 invalid；401；403 access/consent/hold；404；409 state/idempotency/source/policy changed；412；422 `AI_CAPABILITY_NOT_ALLOWED/AI_INPUT_NOT_ELIGIBLE/AI_OUTPUT_INVALID`; 429 quota；503 provider/key/policy/service unavailable。provider原始错误不出wire。

## 8. 事件、审计与RLS

事件只含job/capability/source type+ID/version、policy/prompt/model identifiers、status、artifact hash可空和controlled error；不含input/output/prompt/token/cost exact/provider raw ID。目标Context不会消费`AIOutputReady`自动写事实。

Audit保存actor/purpose/source/capability/versions/result/artifact source/人工accept/reject，不保存内容。日志/trace/dead letter递归秘密sentinel。

独立 `ai_gateway` schema包含policies/prompts/current selectors/jobs/input manifests/attempts/artifacts/evaluations/receipts。raw provider buffer不在普通DB。全部FORCE RLS：User只见自己的job；party按resource关系；worker只见leased exact job；publisher/evaluator按assignment；PUBLIC无权限，在线role非owner/无BYPASS。

## 9. TDD与追踪

1. 发布AI OpenAPI、policy/input/output/event schemas；禁止能力不可表示、unknown/secret contract RED→GREEN。
2. Domain RED覆盖policy/job/artifact状态、expiry/hash/retry与source drift。
3. Application RED覆盖exact ports/consent/hold、minimization、injection、provider unknown、validator、人工adopt不dispatch、receipt/fault。
4. fake provider GREEN并保持所有业务command只能显式人工调用。
5. 真PG18 RLS/lease/receipt + provider sandbox/adversarial/eval门禁；production feature flag仍默认off。

| REQ | DESIGN | TEST | CODE | 状态 |
| --- | --- | --- | --- | --- |
| `REQ-AI-001` | DES-AI-001 · §1/2 | `TEST-CONTRACT-AI-POLICY-001` | planned | design |
| `REQ-AI-002` | DES-AI-002 · §3 | `TEST-AUTH-AI-INPUT-001`, `TEST-SEC-AI-INJECTION-001` | planned | design |
| `REQ-AI-003` | DES-AI-003 · §4/5 | `TEST-APP-AI-JOB-001`, `TEST-APP-AI-ADOPT-001` | planned | design |
| `REQ-AI-004` | DES-AI-004 · §6 | `TEST-EVAL-AI-001` | planned | design |
| `REQ-AI-005` | DES-AI-005 · §7/8 | `TEST-DB-AI-RLS-001`, `TEST-SEC-AI-PRIVACY-001` | planned | design |

只有有效RED后标red，相同断言/评测/真实依赖GREEN后标green；production模型仍需单独审批。
