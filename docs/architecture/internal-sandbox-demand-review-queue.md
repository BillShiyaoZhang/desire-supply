# INTERNAL_SANDBOX Demand 审核队列与闭环

> 状态：`BACKEND IMPLEMENTED / FRESH-STACK E2E PENDING / INTERNAL_SANDBOX ONLY / G2 NO-GO`
> 适用范围：合成 Demand 的待审核队列、独立 Reviewer 领取、结构化退回和验证。
> 不授权：真人研究、真实业务资料、合同、资金、现实权益决定或公开服务。

## 1. 用户结果

平台职责为 `OPERATIONS_REVIEWER` 的内部合成账号必须能在浏览器完成下面的真实持久化闭环，而不依赖管理员手写 SQL、seed assignment、Memory fallback 或固定按钮旅程：

1. 查看由已提交 Demand 动态形成的待审核队列；
2. 以 `If-Match` 和 `Idempotency-Key` 领取一个 exact submission/version；
3. 读取领取后才开放的完整审核投影；
4. 发现误领、工作量不足或本人存在冲突时，选择关闭原因释放当前分配，而不伪造审核结论；
5. 二选一完成审核：结构化 `REQUEST_CHANGES`，或结构化 `VERIFY`；
6. 需求方从 exact version 收到 finding、创建新不可变版本并重新提交；
7. 数据库重启后 assignment、release fact、review、audit、outbox 和 receipt 仍可恢复。

队列不是另一份任务真相源。`Demand.status = SUBMITTED`、当前 submission/version 和“不存在未过期 ACTIVE assignment”共同形成权威队列。读取队列不创建业务事实；领取才创建 assignment。`CONFLICT_DECLARED` 的释放事实还会按 Reviewer + exact submission/version 从该 Reviewer 的队列与 target discovery 中排除，避免其立刻重新领取同一对象；其他 Reviewer 仍可领取。`WORKLOAD_RELEASE` 不建立冲突禁领，可由原 Reviewer 再次领取。

## 2. HTTP 契约

正式产品边界使用四条 `/v1/app/*` 路由：

```text
GET  /v1/app/review-queue
POST /v1/app/review-queue/{demand_id}/claim
POST /v1/app/demands/{demand_id}/review-assignments/{assignment_id}/release
POST /v1/app/demands/{demand_id}/review-assignments/{assignment_id}/verify
```

`claim` 要求 `If-Match`、`Idempotency-Key`、同源 Origin 和 CSRF；body 必须是空对象。`If-Match` 绑定 queue item 中的 Demand aggregate revision。重复相同 key/payload 逐字返回同一 assignment；相同 key 不同 target/revision 返回 `409 IDEMPOTENCY_KEY_REUSED`。两个 Reviewer 并发领取同一 submission 时只能一个成功，另一方得到不披露占用者的 `409 REVIEW_ALREADY_CLAIMED`。

`release` 同样要求 `If-Match`、`Idempotency-Key`、同源 Origin 和 CSRF，且 body 精确关闭为 `{"reason_code":"CONFLICT_DECLARED | WORKLOAD_RELEASE"}`。它只能由当前 ACTIVE assignment 的 Reviewer 执行：成功把 assignment 以 CAS 转为 `REVOKED`、保留 Demand 为 `SUBMITTED`、递增 Demand revision，并返回完整 `EditorResource`；其中 `review_assignment = null`。它不创建 review/finding，也不改变正文或提交版本。`CONFLICT_DECLARED` 表示本人不应再领取这个 exact submission/version；`WORKLOAD_RELEASE` 只表示释放工作量。

队列 item 只返回：

```text
demand_id
demand_revision
demand_version_no
submitted_at
demand_expires_at
etag
```

领取前不返回 Organization、owner、正文、预算、私密字段、assignment、其他 Reviewer 或冲突原因。领取后复用 assignment-bound Demand read model。

`verify` body 关闭为：

```json
{
  "budget_health_code": "HEALTHY | APPROVED_EXCEPTION",
  "risk_code": "STANDARD | ELEVATED_APPROVED",
  "evidence_codes": [
    "SCOPE_COMPLETE",
    "ACCEPTANCE_TESTABLE",
    "BUDGET_COHERENT",
    "RISK_HANDLED",
    "DECLARATIONS_CONFIRMED"
  ]
}
```

列表必须非空、去重且仅含关闭 code；服务端按 UTF-8 byte 排序后生成 evidence summary digest，浏览器不能提交 digest、reviewer、duty、Organization、状态、时间或 Gate 字段。`REQUEST_CHANGES` 继续使用关闭 reason codes 和 JSON Pointer field paths，由服务端映射 Demand field code。

## 3. IAM 与职责分离

旧 `lock_demand_reviewer_session_v1` 只证明 Session ACTIVE，不能证明当前 Reviewer duty。它保留为历史 migration 字节，但从 online role 撤销 EXECUTE；新写路径只使用：

```text
iam_api.lock_demand_review_claim_authority_v1(...)
iam_api.resolve_demand_reviewer_authority_marker_v2(...)
iam_api.lock_demand_reviewer_authority_v2(...)
```

领取 capability 按 Family → Session → User → Organization membership absence → `OPERATIONS_REVIEWER` duty grant 锁定。它必须返回 exact duty grant ID/version/expiry 和 marker；缺失、撤销、过期、marker 漂移、Reviewer 是 Demand creator，或 Reviewer 在 owner Organization 有 ACTIVE Membership 时均返回零行。

assignment 持久保存 exact duty grant ID/version、submission/version、conflict attestation digest、领取 marker、expiry 和 aggregate version。`REQUEST_CHANGES`/`VERIFY`/`RELEASE_REVIEW_ASSIGNMENT` 每次再次锁 IAM duty，并与 assignment 的 ID/version exact compare；数据库 role、浏览器 role 字符串和旧 principal snapshot 都不是权限。IAM43 只把这个 exact 新 operation 加入现有 reviewer authority v2 allowlist；`NULL`、未知 operation、marker 漂移或已撤销 duty 均返回零行。

首版 assignment TTL 固定为 30 分钟，不接受客户端配置。过期 assignment 在下一次领取事务内以 CAS 转为 `REVOKED`，不会被原 Reviewer 继续使用，也不会永久堵塞队列。

## 4. PostgreSQL 事务协议

领取使用 `demand_review` role-bound pool 和固定程序，不允许 generic SQL executor：

```text
preflight PG18 / exact role / IAM head / Demand head
BEGIN READ COMMITTED
derive immutable Organization ID from demand_id (non-locking fixed lookup)
lock IAM Family → Session → User → duty / prove no owner-org membership
lock Demand root → current submission/version → prior assignment
claim idempotency receipt
CAS expected Demand revision and exact SUBMITTED pointers
revoke only an expired ACTIVE assignment, if present
insert one ACTIVE assignment
insert append-only audit
insert demand-v1 outbox event
complete receipt
COMMIT
```

assignment insert不改变 Demand aggregate revision；`If-Match` 只防止领取已经换版、撤回或完成的 submission。assignment 自身从 version 1 开始。唯一 partial index 保证一个 Demand 最多一个 ACTIVE assignment；事务还逐字段验证 submission/version/content hash 指针。

receipt 不存 raw Idempotency-Key、Session/CSRF、正文或冲突细节。claim 的安全响应只保存 assignment ID/status/expiry、Demand ID/revision 和 strong ETag。任何缺字段、未知键、hash/key/canonicalizer 漂移或 partial chain 都 fail closed。

领取的 audit action 固定为 `CLAIM_DEMAND_REVIEW`；outbox event 固定为 `DemandReviewClaimed`，payload 只含 Demand ID、version ID 和 `SUBMITTED`，不含 assignment ID、Reviewer、duty、Organization label 或正文。audit/outbox/receipt 与 assignment 同事务；任一写点失败全部回滚。COMMIT acknowledgement loss 对外为 `COMMAND_OUTCOME_UNKNOWN`，只能用同一 key 恢复。

释放事务遵守同一全局锁序：先锁 IAM Family → Session → User → Reviewer duty，再锁 Demand root 与 exact ACTIVE assignment，随后 claim receipt、写 immutable release fact、CAS assignment 为 `REVOKED`、递增 root revision、写 audit/outbox 并完成 receipt。释放 audit action 固定为 `ReleaseDemandReviewAssignment`，IAM authority operation 固定为 `RELEASE_REVIEW_ASSIGNMENT`，事件固定为 `DemandReviewAssignmentReleased`。release fact 保存 assignment、Reviewer、exact submission/version、关闭 reason、释放时间与 command identity；禁止 UPDATE/DELETE。完成收据恢复必须先于 ACTIVE target discovery，因此 COMMIT acknowledgement 丢失后 assignment 已不可见时，原 key 仍能逐字恢复成功响应；同 key 不同 payload 仍冲突。

## 5. RLS 与最小权限

所有新 receipt 表 `ENABLE + FORCE RLS`，PUBLIC 无 schema/table/function 权限。跨租户 queue scan 只能经 `SECURITY DEFINER` 固定函数，固定 `search_path`、静态 SQL、exact `session_user/current_user/GUC` 和 IAM capability；`demand_review` 不获得无条件 `SELECT demands`、IAM 表读取权或 INSERT assignment 权。

领取函数是 assignment INSERT 的唯一 online capability。普通 Reviewer target discovery 仍只返回本人未过期 ACTIVE assignment，并在 list、resolve 与 direct claim 三层排除本人对当前 submission/version 的 `CONFLICT_DECLARED`；owner read model 不返回 assignment identity。伪 GUC、错误 workspace、过期 Session/duty、跨 actor/target、重复或篡改 receipt 均不得读取或写入任何其他 Demand。

`SELECT ... FOR UPDATE/SHARE` 除 SELECT RLS 外还需要对应的 UPDATE RLS。领取路径因此只向 `demand_schema_owner` 增加 exact `CLAIM_REVIEW`、Organization、Demand、actor、Session 上下文绑定的 root/submission/version 锁策略；online role 不获得这些表的新直接写权限。

## 6. RED → GREEN 与完成证据

1. contract/HTTP RED：关闭 body、必须 headers、queue 最小投影、verify code allowlist；
2. IAM 真实 PG18 RED：duty 缺失/撤销/过期、owner-org member、错 marker、v1 EXECUTE 均拒绝；
3. Demand 真实 PG18 RED：队列隔离、领取与释放的幂等/OCC/并发、过期重领、冲突禁重领、RLS、audit/outbox/receipt 原子性；
4. application RED：生产 service 无 queue UoW 时 fail closed，不允许 Memory fallback；
5. composition RED：production 只在 v2 IAM、Demand queue fixed functions 和 VERIFY UoW 全部 ready 时监听；
6. PostgreSQL 18 GREEN 后再做空数据库 migrate → identity bootstrap → 分别登录独立 Demand Owner 与 Operations Reviewer 账号 → submit → claim → workload release/reclaim → conflict release/换 Reviewer claim → request changes → resubmit → claim → verify → restart E2E。

当前已获得 IAM duty authority、Demand queue list/claim/release/replay/OCC/并发、release 七个写入 checkpoint 全回滚、冲突禁重领/工作量可重领、撤权后 VERIFY 无 partial write，以及完整 Demand UoW 的真实 PostgreSQL 18 GREEN。空数据库整栈 migrate、独立账号浏览器旅程与重启恢复仍由 fresh-stack E2E 门禁负责；在其完成前本纵切只声明 backend implemented，不声明平台完成或 G2 可用。

静态 SQL、fake connection 或 Memory 测试只能作为前置证据，不能替代第 2、3、6 项。
