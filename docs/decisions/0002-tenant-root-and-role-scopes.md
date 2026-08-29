# ADR-0002：组织租户根与角色作用域

> 状态：已接受
>
> 日期：2026-08-07
>
> 决策驱动：首个平台 API 必须同时支持个人创作者、组织需求方、多组织成员关系和默认拒绝授权，且不能靠隐式“当前租户”掩盖跨组织访问。

## 背景

[目标平台领域模型](/architecture/platform-domain-model.md)已经规定 `User — Organization` 经 `Membership` 形成多对多关系，组织角色不能自动授予项目字段访问；[目标平台架构](/architecture/target-platform.md)又要求授权同时检查角色、资源关系、状态、字段可见性和 hold。但现有设计尚未决定：

- 是否为每个个人创作者自动创建一个“个人组织”；
- `CREATOR`、`DEMAND_OWNER`、`PROJECT_MEMBER` 和平台运营角色各自属于什么作用域；
- 多组织用户的当前组织由 session、请求还是资源关系决定；
- PostgreSQL 如何在应用策略之外阻止跨租户读写；
- 当前 MVP 的 `client_org_id` 能否直接成为目标平台 Organization ID。

这些选择会改变所有后续档案、需求、匹配、项目和支付表的外键与授权语义，必须在第一个平台切片前固定。

## 决策

### Organization 只表示真实组织租户

`Organization` 是组织拥有资源的租户根，表示真实存在的企业、非营利组织、社区、采购团队或经批准的小型创作者团队。个人用户不会仅为满足技术统一性而自动获得虚构的“个人组织”。

以下对象保持全局主体：

- `User` 与其外部认证身份；
- 个人 `CreatorProfile` 及用户对它的所有权关系；
- 用户自己的政策接受、同意、会话和数据权利请求。

以下对象必须属于一个 Organization：

- `Membership` 与组织角色；
- 组织发出的成员 AccessInvitation；
- 组织作为需求方拥有的 Demand、采购授权和后续交易资源；
- 任何未来以团队而非个人为主体拥有的档案或项目资源。

个人创作者加入真实创作者团队时使用显式 Membership；团队档案和个人档案之间的关系留给 Creator Profile 切片设计，不能用自动创建个人租户提前决定。

### 角色按作用域拆分

角色代码保持[目标平台领域模型](/architecture/platform-domain-model.md#23-角色)中的规范名称，但授权事实按作用域分表、分配和校验：

| 作用域 | 角色 | 首切片处理 |
| --- | --- | --- |
| 用户账户 | `CREATOR` | 由受控的创作者 AccessInvitation 授予；允许创建并拥有自己的 CreatorProfile |
| Organization Membership | `ORG_ADMIN`、`DEMAND_OWNER` | 只在明确的 organization_id 下有效；由同组织 ORG_ADMIN 在白名单内管理 |
| Project / case assignment | `PROJECT_MEMBER`、`MEDIATOR`、`RULING_PANEL`、`APPEAL_REVIEWER` | 后续切片实现；角色资格本身仍不足以访问未分配资源 |
| 平台职责 | `OPERATIONS_REVIEWER`、`FINANCE_OPERATOR`、`TRUST_OFFICER`、`SYSTEM` | 仅经受控内部配置、职责分离与审计授予；不存在组织管理员授予入口 |

一个 User 可以同时拥有多个作用域的角色。每次授权必须使用具体 action、resource 和 resource organization/project/case relationship；不能把“用户拥有某个角色”解释为对同类全部资源的访问权。

ORG_ADMIN 可以邀请另一个 ORG_ADMIN 或 DEMAND_OWNER，但必须满足近期 MFA、组织仍为 ACTIVE、操作者属于同一组织、目标角色在组织白名单内，且暂停或撤销操作不得使组织失去最后一个 ACTIVE ORG_ADMIN。ORG_ADMIN 不能授予 `CREATOR`、项目/案件角色或平台职责。

### 请求不保存隐式 active tenant

组织资源由路径或资源本身明确给出 `organization_id`。BFF session 只保存 User、认证强度和 session 状态，不保存具有授权意义的角色快照或唯一 `active_organization_id`。

客户端可以保存纯界面偏好的“最近组织”，但服务端不得据此补全缺失的组织边界。授权决策使用：

```text
allow(user, action, resource, field)
  if user and session are active
  and the required policies/consents are effective
  and the role is valid in its declared scope
  and user has the required resource relationship
  and organization/project/case state allows the action
  and field visibility allows disclosure
  and no applicable hold blocks the action
```

未知、跨组织或不可披露资源对普通调用者统一表现为不存在；运营 break-glass 不能通过选择另一个 active tenant 实现。

### PostgreSQL 实施双层租户隔离

每张组织拥有的表显式保存 `organization_id`。子表通过包含 `organization_id` 的复合外键引用父表，防止合法 ID 被连接到另一个组织的父记录。

首版 PostgreSQL 同时使用：

1. 应用授权策略和显式 scope 参数；
2. 对组织表启用并强制 Row-Level Security；
3. 事务级设置经已认证中间件验证的 user_id、organization_id 和 command context；
4. 普通应用数据库角色没有 `BYPASSRLS`，也不是表 owner；
5. schema migration、恢复和紧急维护使用独立身份，不复用在线应用凭据；
6. SYSTEM 命令仍按单个明确组织设置 scope，不能把跨租户直连作为普通 worker 默认。

全局 User、ExternalIdentity、Session 和政策接受表不伪造 organization_id；它们只通过 IAM 模块的专用仓库读取，不能成为其他 Context 的通用查询入口。其本人读取、认证协议和 SYSTEM 操作使用 [ADR-0004](/decisions/0004-iam-onboarding-persistence-and-postgres.md) 定义的 operation-scoped FORCE RLS，不把 organization_id 规则错误套到 global row，也不提供无条件跨主体旁路。

### Legacy 标识只作为外部引用

当前 MVP 的 `client_org_id`、creator ID 和 pilot ID 是匿名兼容边界，不是目标平台 User 或 Organization 身份。导入时只保存为 `legacy_source_ref`，需要受控映射和人工证据才能关联新 Organization。不得根据相同字符串、联系人或 `consent_version` 自动创建 Membership、角色或租户。

## 被否决的方案

### 为每个 User 自动创建个人 Organization

该方案让所有角色看似统一，但会把“组织”变成技术容器而非真实业务主体，模糊个人 CreatorProfile 所有权、组织采购授权和未来团队档案，增加删除、账单和合规歧义，因此不采用。

### 把所有角色都保存为 Membership role

这会迫使平台职责和个人创作者能力依赖虚构组织，并可能让组织管理员授予超出组织边界的权限，因此不采用。

### 在 session 中保存角色和 active organization

该方案减少读取次数，但会产生角色撤销延迟、跨标签页 confused-deputy 风险，并允许遗漏组织参数的端点静默使用旧租户，因此不采用。

### 每个租户独立数据库

它能提供更强物理隔离，但会显著提高首个模块化单体的迁移、分析、运营和恢复成本。当前采用共享 PostgreSQL schema + RLS + 复合约束；若未来出现监管或规模证据，再用新 ADR 评估物理拆分。

## 后果

- 后续组织资源从第一张表开始就必须带 `organization_id`，不能事后补租户列。
- Creator Profile 需要同时处理个人所有权与未来团队委托，但不会被虚构个人租户绑死。
- 授权实现需要区分 user role、membership role、resource assignment 和 platform duty，不能只维护一张无作用域 roles 表。
- 普通请求多一次当前关系/状态检查，换取撤销立即生效与清晰审计。
- RLS 不替代应用授权；应用测试和真实 PostgreSQL 策略测试都属于合并门禁。
- 当前 MVP 数据不能自动获得目标平台身份或租户权限，迁移需要显式映射和重新确认。

## 验证义务

- `REQ-TENANT-001` / `DES-TENANT-001`：同角色跨组织的直接、关联、分页和写入均失败，测试必须运行真实 PostgreSQL RLS。
- `REQ-TENANT-002` / `DES-TENANT-002`：ORG_ADMIN 只能管理本组织白名单角色，不能授予账户、项目、案件或平台角色。
- `REQ-TENANT-003` / `DES-TENANT-003`：Membership 暂停只影响对应组织；User 暂停影响全部 session 和作用域。
- `REQ-MIG-IAM-001` / `DES-MIG-IAM-001`：legacy ID 只形成外部引用，不自动形成 User、Organization、Membership 或角色。

对应 API、表、状态机和 TEST ID 见 [身份、租户、政策同意与会话设计](/architecture/identity-tenancy-consent.md)。
