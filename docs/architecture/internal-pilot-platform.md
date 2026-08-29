# 内部试运行平台：账号、可编辑工作区与部署边界

> 状态：`IMPLEMENTATION CANDIDATE v0.1 / G1 NO-GO / G2 NO-GO`
> 适用范围：可部署的软件工程纵切、内部受邀账号、合成或虚构业务数据、provider sandbox
> 不授权：外部真人参与、真实业务资料、合同、资金、现实权益决定、公开注册或公开发布
> 发布边界：本文不授权向 OpenAI Sites 或任何外部托管平台发布；服务器部署由获授权操作者在 Gate 与运行检查通过后执行

## 1. 决定

本轮不把 `local_synthetic` 的 persona picker 和 SQLite 单场景改名为“真实平台”。保留它作为确定性的制度回归 fixture，另建 `internal_pilot` 组合根和 `/v1/app/*` 产品接口。

新纵切遵循六项决定：

1. 账号采用**邀请制外部 OIDC + 服务端 opaque Session**，平台不保存本地密码；
2. User、Organization、Membership、RoleGrant 和 Session 复用现有 IAM 领域及 PostgreSQL 18 schema；
3. 角色按账号、组织、平台职责和资源分配四层表达，不提供可任意编辑的全局 `roles[]`；
4. Profile、Demand、Review、Agreement、Delivery、Reconciliation 和 Appeal 使用服务端草稿与不可变提交版本，不把流程压成下一步按钮；
5. 浏览器只访问同源 Web/BFF，API 和 PostgreSQL 不直接暴露公网；
6. 默认部署 profile 为 `INTERNAL_SANDBOX`。真实参与者能力不能靠一个环境变量开启，必须验证版本化 Gate activation artifact。

## 2. 运行 profile

| Profile | 身份 | 数据 | Provider | 可用范围 |
| --- | --- | --- | --- | --- |
| `LOCAL_SYNTHETIC` | 固定合成 persona | 可重置 SQLite fixture | 无外部调用 | 本机制度演练与回归测试 |
| `INTERNAL_SANDBOX` | 受邀内部 OIDC 账号 | PostgreSQL；只允许合成、虚构或明确获批的内部测试数据 | OIDC sandbox；资金/通知/文件均为关闭 adapter 或 sandbox | 可部署的内部试运行与工程观察 |
| `CONTROLLED_PILOT` | 受邀批次账号 | 仅获批批次数据 | 获批 provider | 当前不可激活；必须满足 G2 全部门槛 |
| `PUBLIC` | 公开注册 | 生产数据 | 生产 provider | 未实现且 G3 NO-GO |

`INTERNAL_SANDBOX` 的页面、健康摘要和审计快照必须持续显示 `G1 NO-GO / G2 NO-GO` 与“禁止真实数据、合同和资金”。服务端拒绝客户端提交 `deployment_profile`、`actor`、`role`、`organization_id` 或 Gate 状态来提升权限。

`CONTROLLED_PILOT` 的未来启动条件不是 `EXTERNAL_PARTICIPANTS_ENABLED=true`。组合根必须读取签名或 digest 固定的 activation artifact，至少绑定：

- Gate review ID、批准状态和有效期；
- release revision / image digest；
- 地域、组织、账号、项目、金额和数据类别上限；
- provider、合同、隐私与运营版本；
- stop authority、停止阈值和善后负责人。

artifact 缺失、过期、范围不匹配或无法验证时，进程在监听端口前失败关闭。

## 3. 账号与认证

### 3.1 登录模型

唯一正式登录链路是 OpenID Connect Authorization Code + PKCE：

```text
受控邀请 URL
→ 平台创建 AuthTransaction(state / nonce / PKCE / browser binding)
→ OIDC provider 认证、恢复密码和 MFA
→ callback 严格验证 issuer / audience / nonce / time / subject
→ invitation 与 verified contact exact binding
→ 激活 User 和一个 exact grant
→ 建立并轮换服务端 Session family
→ 设置 __Host-ds_session
```

公开 signup 永久关闭。未知 OIDC subject 在没有有效邀请时不得创建 User；相同邮箱不能作为账号自动合并依据。平台不提供 password、password hash、reset token 或管理员代设密码功能。

Session cookie 固定为：

```text
__Host-ds_session; Secure; HttpOnly; SameSite=Lax; Path=/
```

数据库只保存 keyed handle digest。登录、step-up 和邀请接受后轮换 Session 与 CSRF；账号暂停、Membership/职责撤销和旧 handle replay 必须使权限即时收敛。

### 3.2 四层角色

| 层 | 角色或职责 | 作用域 | 授予方式 |
| --- | --- | --- | --- |
| Account | `CREATOR` | 单一 User | creator invitation；本人接受 |
| Organization | `ORG_ADMIN`、`DEMAND_OWNER` | 单一 Organization Membership | 同组织管理员邀请；本人接受 |
| Platform duty | `ACCESS_ADMIN`、`OPERATIONS_REVIEWER`、`FINANCE_OPERATOR`、`TRUST_OFFICER`、`APPEAL_REVIEWER` | 平台资格，有起止时间和撤销事实 | bootstrap SYSTEM 或 ACCESS_ADMIN 的关闭命令 |
| Resource assignment | selector、签约人、验收人、受益者代表、付款发起人、reconciler、case/appeal reviewer | exact Demand / Project / Payment / Case | 资源 owner 的版本化 assignment |

平台 duty 只表示资格，不自动授予业务对象访问。高风险动作同时要求 exact assignment、当前 duty grant、无冲突、近期 MFA 和资源版本。

禁止：

- 通用 `PATCH user.roles`；
- 管理员替接收者接受邀请；
- `ACCESS_ADMIN` 自授职责或移除最后一个有效 `ACCESS_ADMIN`；
- `ORG_ADMIN` 授予平台职责或跨组织角色；
- payment initiator 对同一 obligation 执行 reconciliation；
- 原始 case decider 审理同一 appeal。

### 3.3 账号管理命令

首个管理面只提供关闭命令：

```text
IssuePlatformAccessInvitation
GrantPlatformDuty
RevokePlatformDuty
SuspendUser
ResumeUser
RevokeAllUserSessions
UpdateMyDisplayHandle
```

所有管理写请求要求 `Idempotency-Key`、`If-Match`、当前 CSRF、稳定 `reason_code` 和近期 MFA。`SuspendUser` 原子撤销全部 Session family，但不删除交易、付款主张、数据权或申诉事实；`ResumeUser` 不恢复旧 Session 或已撤销 grant。

## 4. 可编辑对象模型

### 4.1 统一规则

每个可编辑资源都有独立聚合版本和 ETag，不再使用“整个场景一个 revision”。

```text
Aggregate
  current_state
  aggregate_version
  current_draft_id?
  current_submitted_version_id?

Draft
  draft_id
  based_on_version_id?
  draft_revision
  owner_assignment_id
  content
  last_saved_at

SubmittedVersion
  version_id
  version_no
  canonical_content
  content_sha256
  submitted_by
  submitted_at

Finding
  finding_id
  target_version_id
  field_path
  code
  detail
  responsible_role
  status
  due_at?
```

规则：

- 禁止隐式 autosave；“保存草稿”是明确命令和持久事实；
- 提交、发布、确认后的版本不可原地修改；
- 退回产生绑定 exact version 的 Finding，并从该版本 fork 新草稿；
- repeater 条目有稳定 item ID，差异能区分新增、删除和修改；
- 一个草稿只有一个当前 owner；其他角色通过 Finding/InputRequest 协作；
- 412 返回最小 `base/current/yours` 三方比较材料，客户端不能自动覆盖；
- 网络结果未知时只允许以同一 Idempotency-Key 恢复，不生成新动作。

### 4.2 第一纵切

第一条可上手纵切只贯通以下实体：

1. Creator Profile 草稿、发布和版本比较；
2. Organization Demand 列表、草稿、十三组字段、九角色 assignment、提交；
3. Demand Review assignment、结构化 findings、退回修改或 verify；
4. 任务首页与实体详情路由；
5. 审计时间线和内部观察事件。

Profile 内容复用 `profile-version-v1`：interests、skills/evidence、availability、collaboration、private compensation、private boundaries、location、conflicts 和 AI 规则。需求方、运营者或其他创作者的 read model 不得包含 private compensation/boundaries。

Demand 内容复用 `demand-content-v1`：problem、scope、acceptance、skills、matching、schedule、budget、milestone plan、risk、AI、collaboration、location、declarations。九角色 assignment 是独立版本化事实，不嵌入自由文本。

### 4.3 后续纵切

第二纵切：AgreementVersion、Milestone、DeliveryDraft/Version、criterion-based Acceptance 和 BeneficiaryOutcome 分离。

第三纵切：Funding/Payment request 与独立 Reconciliation、Safety case、Appeal、Consent/Data Rights。资金状态在 `INTERNAL_SANDBOX` 中只接受 sandbox ledger 事实，不能把截图、人工按钮或 provider timeout 变为 `SECURED/PAID`。

## 5. 产品接口与页面

正式产品 API 使用 `/v1/app/*`，不得复用 `/v1/local/*`：

```text
GET  /v1/app/configuration
GET  /v1/app/bootstrap
GET  /v1/app/tasks
GET  /v1/app/profiles/me
POST /v1/app/profiles/me/drafts
POST /v1/app/profiles/me/drafts/{id}/publish
GET  /v1/app/organizations/{org}/demands
POST /v1/app/organizations/{org}/demands
GET  /v1/app/organizations/{org}/demands/{id}
POST /v1/app/organizations/{org}/demands/{id}/drafts
POST /v1/app/organizations/{org}/demands/{id}/submit
GET  /v1/app/review-assignments/{id}
POST /v1/app/review-assignments/{id}/findings
POST /v1/app/review-assignments/{id}/complete
```

### 5.1 编辑器受控配置

Profile 与 Demand 的 taxonomy bundle 不是用户输入，也不是浏览器构建常量。
选定个人或组织工作区后，Web 必须先以同一个已认证 Session 和
`X-Workspace-Id` 调用 `GET /v1/app/configuration`。当前实现只接受以下闭合投影：

```text
editor-configuration-v1
deployment_mode = INTERNAL_SANDBOX
taxonomy_bundle.status = CURRENT_APPROVED
taxonomy_bundle.bundle_id
taxonomy_bundle.effective_at / effective_until
```

服务端从受管 PostgreSQL Demand rule catalog 的当前有效 singleton requirement
投影 bundle；浏览器不能传 actor、organization、role、status 或候选 bundle 来选择
配置。目录不可用、requirement 未生效/已过期、响应多字段，或所选工作区没有
`CREATOR` / `DEMAND_OWNER` 职责时失败关闭。Web 不保存可编辑 taxonomy state：
创建 Demand 和保存 Profile/Demand 草稿均自动绑定刚解析的服务端 bundle；本地
scratch 只保存用户编辑的分区内容，不保存或恢复 taxonomy ID。审核只读工作区沿用
资源版本已经记录的 bundle，不因读取配置而获得编辑能力。

路径中的 Organization/资源 ID 只是定位信息，授权仍来自 Session、当前 grant 与 assignment。body 禁止 actor、role、authority、organization 和 server timestamp。

页面至少包括：

```text
/app
/app/work/:taskId
/app/profile
/app/demands/:demandId
/app/ops/reviews
/app/projects/:projectId
/app/ops/finance
/app/cases/:caseId
/app/appeals/:appealId
/app/settings/security
/app/settings/rights
```

导航来自服务端 capability。无权用户直接访问 URL 时仍由服务端关闭拒绝，不能以隐藏按钮作为授权。

## 6. 观察与学习

为观察实际运行，平台保存最小、第一方、目的限定的产品观察事件，不接第三方 analytics SDK：

```text
event_id
event_type
occurred_at
pseudonymous_actor_id
organization_id?
resource_type?
resource_id?
workflow_stage?
outcome_code
latency_bucket?
release_id
```

禁止把表单正文、私密 Profile 字段、Contact、Session/CSRF、邀请 token、争议材料、文件内容或任意用户输入复制到 analytics。观察 read model 必须区分：

- 系统事实：提交、拒绝、等待、并发冲突、恢复结果；
- 人的观察：结构化 feedback/Outcome；
- 推断：必须标明算法/规则版本，不得冒充事实。

在 `INTERNAL_SANDBOX` 中，观察只证明内部可运行性，不能证明市场需求、可用性、公平性或制度效果。

## 7. 容器与网络

最小部署拓扑：

```text
Internet / operator
       │ HTTPS
       ▼
edge (Caddy)
       │ internal HTTP
       ▼
web (Vinext BFF)
       │ closed service URL + service identity
       ▼
api (production ASGI composition)
       │
       ▼
postgres:18
```

同一 API image 提供一次性 `migrate` 入口。`backup` 使用独立最小权限凭据，输出加密备份到独立目标。只有 edge 发布宿主端口；Web、API、PostgreSQL 只加入 internal network。

容器要求：

- non-root 用户、只读 root filesystem、临时目录显式 tmpfs；
- secret 以只读 file mount / Docker secret 注入，不写 Compose YAML 或镜像；
- PostgreSQL 使用 named volume，不向公网映射端口；
- readiness 顺序为 PostgreSQL → migrate → API → Web → edge；
- Web 容器内监听 `0.0.0.0`，但本机开发仍精确监听 `127.0.0.1`；
- BFF 上游只允许构建时/启动时固定的 loopback 或 Compose `api` service，不接受请求参数控制；
- SIGTERM 先 not-ready，再有界 drain，最后清理连接池；
- production profile 禁止 Memory/SQLite/fake OIDC fallback。

Dev Container 固定 Node 22、Python 支持矩阵、uv、PostgreSQL client 与 Docker CLI，并使用非 root 工作用户。开发 override 可挂载源码；生产镜像不得挂载源码、`.git`、`.env*`、本地数据库、测试缓存或 `node_modules`。

## 8. 迁移、备份与发布

部署顺序固定：

1. 从 clean checkout 构建带 revision 的不可变镜像；
2. 验证配置、secret 引用、contract digest 和数据库兼容窗口；
3. 执行 forward-only、checksum 固定、可重复的 migration job；
4. 启动 API readiness，再启动 Web/edge；
5. 以测试 OIDC 账号完成多角色 smoke；
6. 重启 API/Web 并验证 Session/草稿/版本保留；
7. 创建备份并在隔离项目完成 restore drill；
8. 记录 image digest、migration head、测试证据和回滚条件。

应用启动不得自动迁移。readiness 不写数据、不修复 schema、不调用真实 provider。数据库 schema 超出兼容窗口、必要 key 缺失、activation artifact 无效或 online role 不匹配时保持 not-ready。

## 9. 验收矩阵

| ID | 验收 |
| --- | --- |
| `ACC-IP-001` | 未认证用户不能选择 persona 或 body role 登录；未知 OIDC subject 无邀请时零 User 写入。 |
| `ACC-IP-002` | 管理员能邀请、暂停、恢复和撤销 Session；权限撤销对既有 Session 即时收敛。 |
| `ACC-IP-003` | 四层角色不能串授、串用或由客户端伪造；职责冲突在服务端拒绝。 |
| `ACC-IP-004` | Creator 保存 Profile 草稿，刷新/重启后恢复；发布 v1 后可从 v1 建 v2 并查看 diff。 |
| `ACC-IP-005` | Demand owner 可编辑十三组字段和九角色 assignment；缺失项返回 field path；提交版不可变。 |
| `ACC-IP-006` | Reviewer 只能对分配的 frozen DemandVersion 添加 Finding，不能修改 Demand 原文。 |
| `ACC-IP-007` | 双 tab 并发产生 412 和三方比较，不发生 last-write-wins。 |
| `ACC-IP-008` | 同 key/同 payload 安全重放；同 key/不同 payload 409；commit unknown 不猜成功。 |
| `ACC-IP-009` | read model 不泄漏其他用户或 Profile private compensation/boundaries。 |
| `ACC-IP-010` | Compose 从空 PostgreSQL 18 迁移并启动；只有 edge 暴露端口；所有应用进程 non-root。 |
| `ACC-IP-011` | 容器重启后 Session、草稿、版本、Finding 和审计仍可读取；已撤销凭据不复活。 |
| `ACC-IP-012` | 备份可在隔离数据库恢复，restore 后权限、撤销事实和 schema head 一致。 |
| `ACC-IP-013` | `INTERNAL_SANDBOX` 拒绝真实资金/provider adapter 与真实数据类别；不能用环境变量绕过 Gate。 |
| `ACC-IP-014` | 观察事件不含正文、token、Contact 或私密字段，并明确只能支持内部运行结论。 |

## 10. 当前实现事实

截至本文版本：

- `local_synthetic` 与当前 `web/` 只能证明合成单场景、多 persona 任务交接；
- IAM 的 OIDC 协议、Session、User/Organization/Membership/RoleGrant、RLS 和部分 PostgreSQL adapter 可复用；
- Profile 与 Demand 已有领域状态机、机器契约和 PostgreSQL fixed-UoW seam；
- 真实 OIDC adapter、production composition、平台 duty/User lifecycle、正式 `/v1/app/*` transport、跨 Context PostgreSQL 纵切、Docker/Dev Container、备份恢复和浏览器多账号 E2E 尚未全部 GREEN。

实现报告必须逐项区分 `CONTRACTED`、`MEMORY-GREEN`、`POSTGRES-GREEN`、`HTTP-GREEN`、`CONTAINER-GREEN` 与 `BROWSER-GREEN`，不得用其中一个状态代替其他状态，更不得把内部工程观察升级为真人或市场证据。
