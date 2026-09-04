# Current-head v28 静态模式头

状态：本轮未发布候选，模式头已对齐 Matching9。Matching9 的 24 项静态与真实 PostgreSQL 回归
通过，包含真实 CHOOSE/CLOSE 完成、回执重放、原 Session 终态读取及错误组织/selection/workload/
marker/scope/operation 拒绝；runtime 直接读取回执仍为 42501。v28 只读 verifier 与 Matching9 对齐后的
251 项聚焦部署测试已通过，证据为
`.local/workflow-evidence-20260904-verified/v28-matching9-deployment-focused.xml`。
Matching8 阶段的 251 项证据另存于 `.local/workflow-evidence-20260904-fixed/v28-matching8-deployment-focused.xml`。
完整 HTTP 四分支、逐条数据库核对、重启后的 HTTP 和数据库连续性均已在干净
`desire-workflow-20260904-verified` 项目通过。先前两个项目保留失败证据，不能记作原任务恢复。
发布校验的声明范围仅为 `STATIC VERIFIED / NOT PRODUCTION EXECUTED`；独立 PG 的 SYSTEM_CLOSE
终态和 CHOOSE/CLOSE 领取回归不代表整条浏览器/HTTP Matching 协作通过，也不授权生产部署。

<!-- BEGIN CURRENT_HEAD_V28_CONTRACT -->

## 精确模式头

v28 将 Matching3 前向升级到 Matching9：Matching4 修复正式 ingest 函数的 PL/pgSQL 名称歧义，
Matching5 修复 coordinator 领取后的 RLS scope 和首次领取审计版本，Matching6 补充固定 reviewer
claim 程序的结果可见性与行锁 policy，Matching7 增加仅限精确 CREATE 成功回执的安全只读 probe，
Matching8 令未来邀请披露的时间文本按 UTC 输出为 v1 所要求的 `Z`，保留微秒精度；Matching9 允许
固定 coordinator 完成程序读取当前 selection 原始选择/关闭意图精确绑定的 USER 回执。
其余组件 head、依赖和 API/event/domain 合同保持 v27 的值。

| 组件 | current / head | 依赖 | manifest / combined SHA-256 |
| --- | ---: | --- | --- |
| PostgreSQL | `18` | — | image digest 由容器合同独立固定 |
| IAM | `46 / 46` | — | `faa540929a66eeb7ebfe86ca5e43539ef7dcb10424e792ded14252f27c5850a5` / `14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d` |
| Profile | `5 / 5` | IAM46 | `005be339b76c61427895ad7e6ddbb685735d7c602d99fc4dafdd08c35c97d4f8` |
| Demand | `15 / 15` | IAM45 migration dependency | `32d8587651d05e725a4277e2d253b8e195192f1dabc702dd5208b53fe8143f73` |
| Trust | `22 / 22` | IAM46 + Demand15 | `3fd3089db8139f4e70551f59f8e803fdf2543847d38d08f82f8a050c2dd921e8` / `68f3c3e90088f6d4383e73b3fbc6f77297cee27bc78086db227708bc872613f6` |
| Matching | `9 / 9` | IAM46 | `ff3453c1f86739684dbe255a6ae16a0b5839dacf7ba680b120a50b089aa260e2` |
| Taxonomy | `2 / 2` | — | `74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622` |

Trust22 对 Demand15 固定的 dependency digest 为
`ea6887891134ffa2f451fed35d469ae1c5195c54649e228f587622d95696dddf`，对 IAM46 固定的 combined
digest 为 `14b0ae7a2ba2db7d6807b9b71080d40ab4b40b4e0e2664c5da0ac14fcb29c84d`。

数据库 backup/restore pin：

```text
18|46|46|5|5|15|15|22|22|9|9|2|2
```

Matching4 文件 `0004_expand__matching_ingest_name_resolution.sql` 的 SHA-256：
`9cd168affafd3d0006a991c803e8d1095b5193da5aea2464648db76b48802c8b`。

Matching5 文件 `0005_expand__matching_coordinator_claim_scope.sql` 的 SHA-256：
`859f003a39317e4b496c4a29d493c0d282bc7e79fcb7736c2cf5700f35fd79c7`。

Matching6 文件 `0006_expand__matching_review_claim_visibility.sql` 的 SHA-256：
`581d9f8e5394f67dba1b659807870c857b84a5ef4464d0197ce7370f611eb499`。

Matching7 文件 `0007_expand__matching_create_invitation_receipt_probe.sql` 的 SHA-256：
`0037718c52ee0d30e6787031ef8a46be7cfddc9847167bb47295c3a0b5b1e649`。

Matching8 文件 `0008_expand__matching_disclosure_utc_timestamp.sql` 的 SHA-256：
`4059c3b2f13bbd5a5a1b51b20becc3fc385a8509dc20f5cd886f6c56585bf8c2`。

Matching9 文件 `0009_expand__matching_completion_intent_receipt_visibility.sql` 的 SHA-256：
`726907b4d5f7f0473bc0b826a59134bb59007d34344bb6ddd4ff70a07a477de9`。

## 前向迁移与历史保存

本次以六个前向迁移修复既有函数、固定 definer policy，并新增一个只读回执入口，保留既有函数签名、runtime 无直接业务表权限、
workload authority、租约、幂等回执和输入冻结边界。Matching6 的两条行锁 policy 使用
`WITH CHECK(false)`，合法 CLAIM 下的普通 UPDATE 与直接读取结果/候选/输入均在真实 PG 返回 42501。
Matching7 只向 matching_review 授予固定函数 EXECUTE；没有新增表权限或 policy。已有回执仍须
匹配当前有效分配、actor/session/marker/org/run 及原始 key/payload/path/version；缺少回执返回空，
payload/version 改动为 409，错误 marker/session 与过期分配为 404。不能通过修改已应用的
Matching1–8 SQL 或已存迁移回执完成升级。

Matching8 只替换原 `expected_invitation_disclosure_v1` 的未来时间生成，保留 SECURITY INVOKER、
函数签名和权限。它不修改已存 snapshot、canonical bytes 或摘要，也不放宽冻结 v1 契约。
Python 在 CREATE 前严格检查带 `Z` 的时间语法和日历值；数据库输出不合法时作为配置错误拒绝。
原合成项目 `desire-workflow-20260904` 的坏快照保留；`desire-workflow-20260904-fixed` 已实际验证
新的合法披露，但其完成任务另因回执 RLS 问题耗尽租约，不能声称先前坏快照或失败任务已恢复。

Matching9 仅新增 `FOR SELECT TO matching_schema_owner` 的精确 policy。session、scope、operation、
组织、selection、workload/marker 均须匹配，且 USER COMPLETED 回执必须由 immutable CHOOSE/CLOSE
意图的 receipt/actor/marker 绑定；不新增表 GRANT 或 UPDATE 权限，不提供失败 job 的 redrive。
`-verified` 项目用于新数据验证；旧失败 job、counter、intent 和历史证据保留原样。

v27 的文档、verifier、schema-pins fixture、三个版本化 operations 资产逐文件保持原始字节，
并由 v28 verifier 固定摘要。新增 `fixtures/current-head-v28/matching-v3-manifest.json` 保存旧前缀；
其 SHA-256 仍为 `b6c4169edcaf4c7cb771fde614ef72c3d90d56b4d2f4d5a0a633f8b634adbf18`。
新 manifest 的前三个描述项和旧 SQL 必须全部一致；v28 verifier 另外固定已应用 Matching4/5/6/7/8 的
原始 SQL 摘要。旧 v27 verifier 不再承担 Matching9 的实时 gate。

## 连续性与恢复边界

`matching_continuity_counts` 继续覆盖 Matching v1-v9 的 27 张 durable domain tables；Matching4/5/6/7/8/9
不增加表。`deploy/postgres-core-facts-v28.sql` 只输出模式元数据、密钥标识符和聚合数量，不输出
Creator/Reviewer/Selector/Candidate 身份、邀请正文、金额、评分、payload 或 safe response。

恢复只允许匹配 `desire-restore-verify-[a-z0-9]{8,32}` 的独立 Compose project 和固定
`desire_restore_verify` 数据库；要求 PostgreSQL18、六组件精确 head/合同、空业务目标、一次事务
restore、恢复后与备份前完整单行事实一致。Matching 27 表和既有 Profile/Demand capture、delivery、
completion 表继续参加空目标与连续性检查。所有备份文件应留在仓库忽略目录。

版本化入口：`deploy/postgres-operations-v28.compose.yaml`。它只重新绑定两个 config 文件，
不更改服务、网络、secret 或执行权限。演练 basename 示例：
`v28-iam46-profile5-demand15-trust22-matching9-taxonomy2-drill01`。

## 校验与声明范围

```bash
python -B scripts/verify_current_head_v28.py
python -B -m unittest tests.deployment.test_current_head_v28_contract -v
python -B -m unittest tests.deployment.test_postgres_operations_v28 -v
```

成功时 verifier 输出 `{"status":"CURRENT_HEAD_V28_STATIC_VERIFIED"}`。该命令只读源码，
不执行 Docker、数据库迁移、restore、业务请求或生产发布。

fresh-volume、既有库升级、Matching 完整业务终态、逻辑 backup/isolated restore、PITR、加密离机备份、
真实 OIDC/供应商联调与桌面/移动 UI 都须按各自实际执行范围记录；任一静态检查不能替代这些结果。
本机合成工作流的动态证据另见[本机 Docker 工作流程验收](docker-workflow-acceptance-2026-09-04.md)。

<!-- END CURRENT_HEAD_V28_CONTRACT -->

```json
{"current_head_v28":{"claim":"STATIC_ONLY","execution":"NOT_PRODUCTION_EXECUTED"},"overall_status":"BLOCKED","production_authorized":false}
```
