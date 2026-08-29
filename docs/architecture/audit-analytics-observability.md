# Audit、Analytics、Outcome 与可观测性

> 状态：Audit & Analytics Context 的权威详细设计；共享 HTTP 边界的低基数、隐私安全 telemetry 已有可执行合同并 GREEN，其余 Audit/Analytics 机器契约仍待提交。
> 适用范围：业务审计、敏感读取审计、不可变checkpoint、事件消费、Outcome/指标投影、数据导出、日志/trace/metrics隐私与RLS。
> 前置依赖：[Outbox](/architecture/outbox-delivery.md)、[数据与安全](/architecture/data-and-security.md)、[目标平台领域模型](/architecture/platform-domain-model.md)与各业务Context事件契约。

## 1. 边界与核心不变量

Audit & Analytics Context拥有 `AuditEvent` 的统一协议/受控查询、`SensitiveAccessEvent`、`AuditCheckpoint`、consumer inbox、分析投影、`OutcomeProjection`、导出job和指标定义。每个业务Context仍在自己的事务中追加AuditEvent与Outbox；Analytics只消费已发布事件或授权snapshot，不反向更新业务聚合。

必须始终成立：

- Audit、日志、trace、指标、搜索、BI、Outcome均不是业务事实来源；
- 通知/分析失败不回滚已提交业务，但业务命令若无法原子写其必需AuditEvent则整体失败；
- 不把“append-only”宣传为不可篡改；数据库权限/trigger、备份和外部签名checkpoint共同提供可检测性；
- BI/运营不直连生产业务表或用schema owner/BYPASSRLS；
- 事件、审计和指标采用字段allowlist，不复制业务JSON、contact、token、私密金额/边界、Agreement/Trust证据正文；
- `Outcome`由Project/Milestone/Funding/Payment/Dispute/Review事件推导，不能由一个管理员表单直接覆盖。

## 2. AuditEvent 协议

每个成功或业务上有意义的拒绝动作追加关闭AuditEvent：

```text
audit_event_id, schema_version
occurred_at, recorded_at
actor_kind, actor_id, original_actor_id
session_id? / workload_credential_id?       # 仅opaque ID
organization_id?, project_id?, case_id?
action, target_type, target_id, target_version?
result = SUCCEEDED | REJECTED | FAILED | OUTCOME_UNKNOWN
reason_codes[]
command_id?, idempotency_receipt_id?
correlation_id, causation_id, trace_id
auth_strength_code?, assignment_id?
policy/rule/content hashes allowlist
```

`occurred_at`是业务决定数据库时间，`recorded_at`是审计插入时间；不接受客户端时间。reason只用published关闭code，异常/SQL/provider自由文本不进入。对未知资源、非披露拒绝，target可用请求target的短期keyed fingerprint而非证明真实ID存在。

Audit不保存request/response body、headers、cookie、CSRF、idempotency key、contact/provider locator、Profile/Demand/Agreement/Delivery/Trust正文、File URL、Evidence、私密budget/floor或raw IP/user-agent。需要安全网络证据时由独立受限security event保存分类/bucket/keyed fingerprint和retention，不扩张通用Audit。

同一业务transaction可以有多个aggregate事件，但只写一个command audit；`command_id`唯一防重复。COMMIT unknown不补写猜测Audit；重建时以receipt+aggregate+audit完整性裁决。

## 3. 敏感读取审计

普通self读取可使用最小访问telemetry；以下操作必须在返回capability/数据前持久追加 `SensitiveAccessEvent`：Trust evidence、完整MatchRunInput、sealed provider reference、break-glass、数据导出、restricted FileVersion、法律/安全case。

AccessEvent绑定actor/assignment/purpose/resource/field-category allowlist、result、deadline、correlation与访问grant version，不保存返回内容。若必需访问审计不可用，敏感读取fail closed 503；不能先返回URL/正文再异步补审计。

普通列表翻页不为每行写Audit；写一个query-level事件，保存operation、scope/filter digest、returned count bucket和cursor version。不得用Audit枚举查询结果ID。

## 4. 完整性与 checkpoint

业务事务内的AuditEvent由append-only表、无UPDATE/DELETE/TRUNCATE online grant与immutable trigger保护。为检测owner/备份层篡改，后台checkpoint job按固定时间窗口和partition：

1. 读取已封闭窗口内全部event `(id, canonical_event_sha256)`；
2. 按ID byte序构造Merkle root/ordered digest；
3. 保存count/min/max/time/root/canonicalization version；
4. 用独立KMS audit-signing key签名并将checkpoint复制到权限分离的WORM/外部存储；
5. 定期复算并报告missing/extra/digest/signature差异。

checkpoint不使单条审计具有法律不可否认性，也不替代备份。窗口在签名后封闭；迟到事件进入下一窗口并记录late source time，不重写旧root。key ID/algorithm/rotation/retention显式保存，旧验证key保留。

## 5. Analytics consumer 与事件缺口

每个projection consumer在同一事务插唯一 `(consumer_name,event_id)` inbox并更新projection。按aggregate保存last applied version：duplicate安全忽略；old version忽略；next version应用；gap进入 `ProjectionGap` 并停止该aggregate，不能跳过或从事件名猜状态。

gap修复只允许：

- 等待迟到事件；
- 从owning Context的授权snapshot port取得exact aggregate/version/hash并创建带source evidence的projection rebuild；
- 运维从已验证备份重放。

不能直接读/写业务表、手工UPDATE last_version或把损坏事件标成功。schema未知隔离并告警。

Analytics只保存明确的de-identified/pseudonymous事实、codes、时间和数值bucket。需要金额精算/合规报表时使用独立restricted financial projection和assignment，不在通用dashboard复制明细。

## 6. OutcomeProjection

`OutcomeProjection`按Project构建，来源manifest至少记录：

```text
project_id pseudonymous key
demand/profile/selection/agreement version hashes
project terminal status and timestamps
milestone planned/completed/accepted counts
funding/payment controlled terminal codes and amount buckets
dispute/review existence and controlled outcome codes
notification-independent workflow durations
source event IDs + aggregate versions
projection schema/rule version + result hash
```

它不保存参与者contact、Profile/Demand/Agreement正文、私密floor/budget exact值、review/Trust narrative或Evidence。需要与真实参与者访谈合并时走独立research consent/subject mapping，不把运营spreadsheet导入Outcome覆盖事件事实。

同一source集合和rule version产生相同hash。规则升级创建新projection version；不覆盖旧结果。project未终态时可有`IN_PROGRESS`投影，但不能冒充最终Outcome。

## 7. 指标、日志与trace

### 7.1 指标

metric label只允许低基数控制值：component、operation、status/error code、event/schema version、role class、region bucket、latency/attempt bucket。禁止actor/user/org/project/case/event/correlation/trace ID、contact、free text、amount、template/skill/domain的无界值。

公平/集中度指标在最小样本阈值以上发布，使用pseudonymous cohort与版本化定义；不从受保护属性推断群体。小样本显示“insufficient data”，不输出可重识别切片。

### 7.2 日志

结构日志allowlist：timestamp、component、operation、outcome、stable error code、latency bucket、短期rotating pseudonymous fingerprints和trace correlation。禁止request/response/event/provider payload、SQL bind values、headers、file paths/content、secrets和业务自由文本。异常调用安全分类器而不是任意`repr`。

当前 `INTERNAL_SANDBOX` 共享 ASGI mux 已实现 `HTTP_BOUNDARY_OBSERVATION_V1`。每个 HTTP 请求在 BFF envelope 内、IAM/Editor/Trust/Appeal 共用 mux 外只产生一条关闭事件；字段精确限制为 `component`、固定 `event_type`、`operation`、`method`、`status_class`、`outcome` 与 `latency_bucket`。operation 只允许 `IAM/EDITOR/TRUST/APPEAL/UNMATCHED`，其余字段也只取关闭枚举；lifespan 不记录。observer 只接收归一化结果，不接收 scope、path、query、header、cookie、token、request/response body、异常正文、actor/object/correlation/trace ID。observer 或时钟失败不改变 HTTP 结果；Uvicorn access log 保持关闭，IAM 原高基数 transport telemetry 在该 composition 中不接线，避免重复记录。

这只是进程 stdout 上的低基数运行 telemetry，不是 `AuditEvent`、敏感读取审计、指标存储、trace、集中采集、告警或长期留存。Docker `local` driver 的大小/文件数上限只约束新建容器的本机 stdout/stderr 保存量，也不能把日志升级为业务证据。

### 7.3 Trace

trace ID/parent关系可跨Context，但span attributes遵守相同allowlist。生产采样不能因错误而自动捕获payload；高风险span默认更低字段而不是更高。traces有短retention与访问分离，不能作为长期Audit。

## 8. 查询、导出与数据权利

Audit查询必须有exact resource relationship或time-bound AuditAssignment/purpose。普通User可查看自己的安全活动最小投影；Organization actor只看本组织且字段allowlist；Trust/Finance/operations只看assignment scope；没有“管理员搜索全库”。

固定keyset分页，cursor HMAC绑定actor/purpose/scope/filter/sort/schema/key IDs。禁止任意字段filter/sort、全文搜Audit正文或offset深翻。

数据导出是job：验证subject/authority与legal holds，冻结query manifest/field allowlist，生成加密artifact，single-recipient短期download capability，读取时SensitiveAccessEvent，deadline后销毁。导出不包含其他主体、provider secrets、restricted case evidence或不可合法披露字段。

删除/更正通过source Context的correction/anonymization事件推进projection；Analytics不直接改业务事实。依法保留Audit可pseudonymize主体但保持事件/纠正链，策略版本与审批可审计。

## 9. PostgreSQL、RLS、备份与恢复

`audit` schema包含audit_events、sensitive_access_events、checkpoint manifests/signatures、query/export assignments/jobs；`analytics` schema包含consumer inbox、projection offsets/gaps、versioned projections/outcomes/metric definitions。

Audit表append-only、分区、FORCE RLS；业务runtime只INSERT规定列，不SELECT全表。query/export role按assignment读取；checkpoint role只读封闭分区并insert checkpoint，无业务UPDATE。Analytics consumer只读outbox安全事件/自己的inbox和projection；BI只读published safe views，无base table。

备份采用加密full + PITR、独立账户/region策略和定期恢复演练。恢复验收不是“数据库能启动”，而是：migration ledger/review pin、aggregate/receipt/audit/outbox/inbox、checkpoint root、projection gap与key references一致；KMS/secret/object artifact也能按runbook恢复或明确fail closed。

RPO/RTO、保留、partition seal和restore cadence在deployment config版本化。restore演练用合成数据，不复制生产隐私到开发。

## 10. API、故障与安全

```text
GET  /v1/me/security-activity
GET  /v1/organizations/{organization_id}/audit-events
GET  /v1/operations/audit-events
POST /v1/me/data-exports
GET  /v1/me/data-exports/{export_id}
GET  /v1/operations/analytics/outcomes
```

所有响应closed/no-store/ETag/trace，export capability单独sensitive。Audit/Analytics写入口不公开；只消费业务transaction或event。

provider/KMS/storage/checkpoint不可用按operation返回503并零partial export/checkpoint。Analytics停滞不影响business write，但必须告警；Audit写不可用使对应business transaction失败。wire不暴露event存在性、assignment、gap内部或retention hold。

## 11. TDD与追踪

1. 发布Audit/Analytics/Outcome/export契约，unknown field/secret/low-cardinality contract RED→GREEN。
2. Domain RED覆盖canonical event、checkpoint、inbox/version gap、Outcome deterministic versions。
3. Application RED覆盖same-transaction Audit、sensitive read fail closed、projection duplicate/out-of-order/rebuild、export capability/expiry、fault/commit unknown。
4. Memory GREEN；不得用log作为Audit或用Outcome回写业务。
5. PG/RLS设计后真PG18 RED覆盖append-only/partition/assignment/BI view、inbox concurrency、checkpoint复算与restore manifest。
6. 备份/PITR/KMS/object store恢复演练和可观测性secret sentinel作为production门禁。

| REQ | DESIGN | TEST | CODE | 状态 |
| --- | --- | --- | --- | --- |
| `REQ-AUDIT-001` | DES-AUDIT-001 · §2/3 | `TEST-CONTRACT-AUDIT-001`, `TEST-APP-AUDIT-ATOMIC-001` | planned | design |
| `REQ-AUDIT-002` | DES-AUDIT-002 · §4 | `TEST-APP-AUDIT-CHECKPOINT-001` | planned | design |
| `REQ-ANALYTICS-001` | DES-ANALYTICS-001 · §5 | `TEST-APP-PROJECTION-001` | planned | design |
| `REQ-OUTCOME-001` | DES-OUTCOME-001 · §6 | `TEST-PROP-OUTCOME-001` | planned | design |
| `REQ-OBS-001` | DES-OBS-001 · §7 | `platform/tests/internal_pilot/test_http_observability_red.py`, composition/server regressions | `http/observability.py`, internal-pilot composition/runtime adapter | partial green：HTTP boundary；集中 metrics/trace/告警仍待实现 |
| `REQ-DATA-EXPORT-001` | DES-DATA-EXPORT-001 · §8 | `TEST-AUTH-EXPORT-001`, `TEST-SEC-EXPORT-001` | planned | design |
| `REQ-RECOVERY-001` | DES-RECOVERY-001 · §9 | `TEST-RECOVERY-PLATFORM-001` | planned | design |

有效RED后才标red；相同断言、适用回归和真实恢复依赖GREEN后才标green。
