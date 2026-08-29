# INTERNAL_SANDBOX Taxonomy 合成 seed 正式闭环

> 状态：`IMPLEMENTED / SYNTHETIC ONLY / G1 NO-GO / G2 NO-GO`
> 适用范围：新 PostgreSQL 18 空库完成四套受审迁移后的离线初始化
> 禁止：真人资料、真实资金、真实权益决定、直接写入 ACTIVE Taxonomy、线上 API 自行 seed、发布到 OpenAI Sites

## 1. 固定输入与结果

唯一允许的 seed artifact 是包内
`desire_platform.internal_pilot.fixtures/internal_sandbox_seed_v1.json`，raw
SHA-256 固定为：

```text
418567e441e6be2744dcc2b3b295764fd303d53c4e13922503130e5cd659552d
```

它固定一个完全合成的 Taxonomy release：

| 事实 | 固定值 |
| --- | --- |
| bundle ID | `50000000-0000-4000-8000-000000000001` |
| family / semver | `PLATFORM_WORK_V1` / `1.0.0` |
| release manifest SHA-256 | `edd4b5bfc1c827080316c043420bfb42a2d3dd3c6eadd1fb65987e812d4836af` |
| selector SHA-256 | `5d98033bf58eb10d03ebc301c1be971e53e23810d7ab77f644b7ff916a610931` |
| Profile consumer | `PROFILE` / `internal_sandbox_profile_seed_job_v1` |

manifest 只描述命令计划，不包含账号密码、HMAC key、真人或业务数据。
`require_executable()` 只有在 artifact raw digest、闭合 JSON、代码生成的完整
release、六个 Demand rule ID 和全部 authority pin 同时吻合时才通过。

## 2. 正式写入顺序

离线程序固定执行以下顺序：

```text
受限 workload authority provisioning
→ 正式 Taxonomy publisher UoW 发布 release
→ 受限 PROFILE consumer authority provisioning
→ 正式 taxonomy_consumer exact capture
→ 正式 consumer inbox claim
→ Profile 本地 inbox + taxonomy marker 原子 apply
→ 管理员精确复验
```

Taxonomy 的 `families`、`selectors`、`bundles`、artifact、node、edge、label、
receipt、audit 和 outbox 全部由既有 publisher UoW 写入。Seed 程序没有 raw
`INSERT ACTIVE` 后门。Profile apply 只接受上述 bundle/release/version，并在一个
事务内写本地 inbox 和 marker；同一事件重放返回既有结果，事件或 marker 漂移则
整笔拒绝。

线上 API 不拥有该 orchestrator，也不持有 migration/publisher/consumer 凭据。
`profile_app` readiness 只可调用：

```sql
SELECT profile_api.internal_sandbox_taxonomy_seed_ready_v1();
```

它只返回一个 boolean，同时证明固定 seed inbox 为 `COMPLETED` 且固定 marker 为
`ACTIVE / release SHA / aggregate_version=1`。没有 seed 或任一事实漂移时返回
`false`；PUBLIC、`profile_matcher` 与 migration runner 均不能执行这个 readiness
程序。

## 3. 角色与凭据来源

CLI 只接收一个已获授权的 PostgreSQL 管理员 secret。它在全局 deployment
advisory lock 内为下列四个既有 `LOGIN / NOINHERIT / NOSUPERUSER /
NOCREATEDB / NOCREATEROLE / NOBYPASSRLS` 角色生成互不相同、至少 32 字符、最长
15 分钟有效的随机密码：

| 角色 | 唯一用途 |
| --- | --- |
| `taxonomy_migration_runner` | 调用两个 digest-pinned authority provisioning 固定程序 |
| `taxonomy_publisher` | 调用既有 publish UoW |
| `taxonomy_consumer` | 调用既有 exact capture 与 inbox UoW |
| `profile_migration_runner` | 调用固定 Profile apply 程序 |

所有数据库连接关闭后，CLI 在释放 advisory lock 前把四个密码全部设为 NULL；任一
安装、写入、复验或清理失败都返回闭合 `BLOCKED`，不会输出 DSN、密码、workload
credential 或 receipt key。

两个 seed runtime secret 也只能来自 `/run/secrets` 下的直接 regular file：

- workload credential：32–256 字节可打印 ASCII，无空白；部署方使用密码学安全
  随机源生成。数据库只保存其 SHA-256。
- receipt HMAC key：精确 32 个非全零原始随机字节；用于生成 publisher receipt
  identity/payload digest，数据库不保存 key。

文件不得是 symlink、不得位于允许 secret root 之外，环境变量不得携带 inline
secret。

## 4. 离线执行契约

先完成受审 schema migration，再由部署环境提供以下变量：

```text
DESIRE_DEPLOYMENT_MODE=INTERNAL_SANDBOX
DESIRE_EXTERNAL_PARTICIPANTS_ENABLED=false
DESIRE_DATABASE_HOST=db
DESIRE_DATABASE_NAME=<reviewed database name>
DESIRE_DATABASE_ADMIN_USER=postgres
DESIRE_DATABASE_PASSWORD_FILE=/run/secrets/<admin file>
DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE=/run/secrets/<ascii credential file>
DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE=/run/secrets/<32-byte raw key file>
```

在已安装 platform distribution、能访问同一 PostgreSQL 18 trusted container
network 的离线部署进程中执行：

```bash
python -m desire_platform.deployment.synthetic_taxonomy_seed apply
```

首次成功只输出固定 manifest digest、bundle ID、`replayed:false` 和
`INTERNAL_SANDBOX_TAXONOMY_SEED_READY`。使用相同两个 runtime secret 再执行时
必须输出 `replayed:true`，且 authority、release、receipt、outbox、consumer inbox
和 Profile marker 的行数均不增加。轮换 workload credential 或 receipt key 后对
同一 seed 重跑属于 drift，必须失败关闭；它不是 key rotation 接口。

## 5. 测试证据要求

合并前至少证明：

1. artifact canonical bytes、digest、release 和 Demand rule IDs 精确；
2. PostgreSQL 18 空库迁移后首跑与同 secret 重跑幂等；
3. publisher/consumer/Profile apply 使用各自正式角色和程序；
4. 非 seed 角色不能调用 authority/projection 程序；
5. marker、authority 或 manifest 漂移失败关闭且不新增第二套事实；
6. provisioning/projector 在 commit 前故障时事务回滚；
7. deployment CLI 无论成功或失败都撤销四个临时数据库密码；
8. 无 seed readiness 为 false，完整 seed 后为 true。

这些证据只授权合成 INTERNAL_SANDBOX 初始化，不解除 G1/G2 NO-GO，也不授权
创建真人账号、真实 Demand/Profile 内容、合同或资金事实。
