# Current-head v24 静态模式头

状态：`CURRENT · STATIC VERIFIED · NOT EXECUTED · INTERNAL_SANDBOX · SYNTHETIC ONLY · G1 NO-GO · G2 NO-GO`。

本页只发布 IAM42 / Profile3 / Demand12 / Trust18 / Taxonomy2 的数据库模式与应用契约当前头。
它不代表迁移、容器、部署或动态演练已经执行，不授予生产权限，且
`production_authorized=false`。

<!-- BEGIN CURRENT_HEAD_V24_CONTRACT -->

## 固定模式头与契约摘要

五域头部按 PostgreSQL、IAM current/head、Profile current/head、Demand current/head、Trust
current/head、Taxonomy current/head 固定为：

```text
18|42|42|3|3|12|12|18|18|2|2
```

静态十段契约按 IAM combined、Profile manifest、Demand manifest、Trust required IAM schema、
Trust required Demand schema、Trust required IAM contract、Trust required Demand contract、Trust combined、
Trust manifest、Taxonomy manifest 固定为：

```text
f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e|4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345|42|12|f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e|379b6cb8b05f7da03905e644d158cfb6ad03409f290d33f63ae80183d428f816|639100c2fd347cdc38e9d9d52686f1a95c17cdcca2fbabe506832d30fad495b1|0b7028c75c8f137bc4a55a76fe73ea956d0c5ada13031f80794b77c1c9535e19|74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622
```

| 项目 | 固定值 |
| --- | --- |
| IAM API / event | `26ffd8243c0baa2580d21e8878897ed0f13aa61fd9ba468cca8edf1fe277477c` / `6af7e75f738bfeef9aeed0ac8e84da782485c1a42e1c937c9d51e66884bad934` |
| IAM 0042 SQL | `1d0c1391f08ba47f0af29d9941634a4f522c0d0c48e0c5747edbed16e4b02f44` |
| IAM manifest / combined | `9c6e0396867d68ac49260684a9531c592055d62cac20d7ebdfb578c236df025d` / `f88bf5f70343edbf06e55c0641b61b58cff27fda48ce00f6489e3f3f80db5a9e` |
| Demand 0012 SQL | `bf76efd70f95a4fa4c49ad43ad03fc9d31e5009bce88364bec851f68b0313280` |
| Demand manifest / dependency | `919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345` / `379b6cb8b05f7da03905e644d158cfb6ad03409f290d33f63ae80183d428f816` |
| Trust / Appeal API contract | `6647e16e9f8f0ab321ed9985eb2da4e591e2217fdaa43ba663355a4f152f44b2` / `ad0fd5874ad6d3343c62334805fe51c088df7b9db9215decfda95ee90a836e46` |
| Trust 0018 SQL | `8623df4ffbd74f360a67fcc05a2a9d3966269458264b042ae10d6f1fd0784c0e` |
| Trust manifest / combined | `0b7028c75c8f137bc4a55a76fe73ea956d0c5ada13031f80794b77c1c9535e19` / `639100c2fd347cdc38e9d9d52686f1a95c17cdcca2fbabe506832d30fad495b1` |
| Trust required IAM / Demand schema | `42 / 12` |
| Taxonomy manifest | `74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622` |

当前字节 pin 冻结在 `tests/deployment/fixtures/current-head-v24/`。其中 IAM、Demand、Trust manifest
与 Trust runner pin 都是只读静态 fixture，不是运行结果。

## ORG_ADMIN 公开名称更正边界

IAM42 是 forward-only 扩展，只新增 `UpdateOrganizationPublicName` public-name correction 命令，不扩大直接表写权限。
调用者必须是当前组织的 ORG_ADMIN，具有最近 MFA，并同时提交当前强 `If-Match`、一个
`Idempotency-Key` 和固定原因 `PUBLIC_NAME_CORRECTION`。目标组织必须与授权组织完全相同。

`canonical public_name` 长度为 1–160 个 Unicode code point，并通过 Cc / Cf / NFC 三项边界：
必须已经是 NFC、首尾无 Unicode 空白，且不含任何 Cc 控制字符或 Cf 格式字符。应用、HTTP、PostgreSQL、Web intent、
响应 parser 与匿名邀请预览使用同一关闭语义。名称不变被拒绝；过期版本只返回
`412 PRECONDITION_FAILED` 与 `current ETag`，不产生 receipt、audit 或 outbox 写入。

原有五条组织管理命令与本命令组成 six-command idempotency family。同一 actor 的同一原始键只可
标识其中一条命令；active 与 retained key candidate 都参与精确查找。成功写入在一个事务内更新名称和
`aggregate_version`，完成 receipt，并各写一条 audit 与 outbox；receipt replay 返回已提交的同一安全响应。

`OrganizationPublicNameChanged` 是失效通知并保持 audit/event name privacy：event payload 只有 `organization_id`，audit 与 outbox
都不保存旧名或新名。anonymous invitation preview 在读取时取得当前公开名称，因此未接受邀请不会冻结旧名。

内部沙箱 bootstrap v6 在调用旧图证明前保存现有 `custom public_name`，只在受保护的事务本地兼容上下文中
临时代入默认名，并在返回前恢复原名称且不改变版本。REPLAY / VERIFY 不得覆盖合法更正后的名称。

已有数据服务器的 IAM42 preflight 在 provisioning advisory lock 后、任何 role/password/catalog 写入前，
以固定 timeout 的 `REPEATABLE READ READ ONLY` 事务扫描全部组织，只返回各类异常的聚合计数。
它与旧 API writer 不在同一事务，不能声称在线扫描与 IAM42 commit 原子；升级必须先停止并排空旧
API/worker，并保持 writer quiescence 直至迁移提交。IAM42 CHECK 是最终竞态门禁，但不替代该静默窗口。

## FINANCE_OPERATOR 本人完成历史边界

Demand12 新增 my completed funding reviews 只读发现入口。当前 `FINANCE_OPERATOR` 必须仍通过 IAM31
的 current-duty `LIST_FUNDING_REVIEWS` 授权，数据库才把事务局部 operation 收窄为历史读取；失去当前职责、
错误 session/marker、非财务角色或直接表读取均 fail closed。

一条历史只在本人 assignment 已 `COMPLETED`，且本人有 own confirmation or own finding 时可见；状态闭集为
`SECURED / DISCREPANCY / REJECTED`。投影只有 funding review、Demand、Demand version、状态与完成时间，
不返回组织、对方核实人、金额、证据或 finding 正文。排序固定为完成时间与 review ID 双降序；分页使用
HMAC actor-bound cursor，跨账号、篡改、不可见或不存在的游标均返回关闭错误。

服务端、HTTP/ASGI、Web BFF 与前端 parser 都执行精确字段闭包。财务工作台显示“我的已完成资金审查”，
支持分页，并在打开既有详情前再次核对 review/Demand/version/status/ETag。真实 PostgreSQL 18 覆盖了 finding
只对提交人可见、SECURED 对两名本人确认者可见、两页 keyset 稳定性与跨 actor cursor 拒绝；完整 Docker
旅程还会在终态和重启后从该入口重新发现记录。

## Trust 与 APPEAL_REVIEWER 本人终态历史边界

Trust17 已发布的 `TRUST_OFFICER` 本人案件历史保持不变：`GET /v1/app/trust/history` 仍只返回
固定最多 100 条 party-safe 导航摘要和 `has_more`。同岗隔离仍由 `trust_officer_01` / `trust_officer_02`
与 `trust_terminal_history_discoverable=true`、`terminal_history_actor_scoped=true` 验证，v24 不扩大该读取面。

Trust18 以 forward-only `0018` 增加 APPEAL_REVIEWER 本人完成复核的 PostgreSQL 18 读取投影。
`GET /v1/app/appeal-review/history` 只允许当前 PLATFORM 工作区、当前 session 和当前
`APPEAL_REVIEWER` duty，拒绝 query/body，固定读取最近 100 条。每条只有 `appeal_id`、
`decided_at`、`decision_code`，按决定时间与 Appeal ID 双降序，`has_more` 只表达截断。
数据库同时核对 decision 的 decider 与 source assignment 的 reviewer，形成双重 actor-bound
约束；两名同岗 reviewer 隔离、时间相同的稳定排序、错误 session、过期或撤销 duty、越界 limit
和 runtime role 直接表读取均 fail closed。

`GET /v1/app/appeal-review/history/{appeal_id}` 只让原决定人 fresh exact terminal detail 读取本人
`DECIDED` 记录。返回是 party-safe 的 application、decision、ETag 与
`review_note_recorded=true`，省略 applicant、reviewer、duty、organization、assignment、source
和 restricted narrative；数据库还要求 sealed review note 的用途与摘要闭合。

task discovery 将本人终态复核映射为 `COMPLETED / APPEAL_REVIEW / VIEW_APPEAL_REVIEW_HISTORY`，
资源入口固定为 `/v1/app/appeal-review/history`。Web 的“我的已完成申诉复核”原子提交 queue、active
assignments 与 history 三项快照；网络失败保留上一份完整验证快照，verified-empty 与 unavailable
不会混淆。完成任务会用 fresh session/workspace/role/tasks/history 重核对 exact 行并把键盘焦点放到该行，
不会信任 task resource path 或按旧 ID 直读。决定写成功还必须同时证明记录离开 active/queue、进入 history，
再 fresh 读取 party-safe 终态详情。Docker/API E2E 的 `_appeal_terminal_history` 与
`_get_terminal_appeal` 只在 `terminal_history_discoverable=true` 和
`terminal_detail_party_safe=true` 成立后给出安全标记。

## 只读静态校验

从仓库根运行：

```bash
python3 -B scripts/verify_current_head_v24.py
python3 -B -m unittest tests.deployment.test_current_head_v24_contract -v
```

v24 校验成功只输出 `{"status":"CURRENT_HEAD_V24_STATIC_VERIFIED"}`。校验只读取已签入文件，不调用
Docker，不运行迁移，不创建 evidence，也不把 `NOT EXECUTED` 升级成动态成功。

## v23 冻结边界

[Current-head v23 静态模式头](/operations/current-head-v23.md) 继续保持
`18|42|42|3|3|12|12|17|17|2|2`。其 fixture 位于
`tests/deployment/fixtures/current-head-v23/`；v24 的 Trust18 Appeal Reviewer history/detail/task/Web/E2E
声明不得写回或冒充 v23 结果。v23 的 `STATIC VERIFIED / NOT EXECUTED` 声明以及已经单独记录的
本地合成动态证据，都没有被重标为 v24 动态执行或生产授权。

```json
{"current_head_v24":{"claim":"STATIC_ONLY","execution":"NOT_EXECUTED"},"overall_status":"BLOCKED","production_authorized":false}
```

<!-- END CURRENT_HEAD_V24_CONTRACT -->

本页成为 current schema pointer 不构成运行授权；任何迁移或部署仍须单独批准并使用独立的新版本运行资产。
