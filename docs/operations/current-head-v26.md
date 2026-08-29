# Current-head v26 静态模式头

状态：`CURRENT · STATIC VERIFIED / NOT PRODUCTION EXECUTED · INTERNAL_SANDBOX · SYNTHETIC ONLY · G1 NO-GO · G2 NO-GO`。

本页只发布 IAM43 / Profile3 / Demand13 / Trust19 / Taxonomy2 的数据库模式与应用契约当前头。
它不代表迁移、容器、部署或动态演练已经执行，不授予生产权限，且
`production_authorized=false`。

<!-- BEGIN CURRENT_HEAD_V26_CONTRACT -->

## 固定模式头与契约摘要

五域头部按 PostgreSQL、IAM current/head、Profile current/head、Demand current/head、Trust
current/head、Taxonomy current/head 固定为：

```text
18|43|43|3|3|13|13|19|19|2|2
```

静态十段契约按 IAM combined、Profile manifest、Demand manifest、Trust required IAM schema、
Trust required Demand schema、Trust required IAM contract、Trust required Demand contract、Trust combined、
Trust manifest、Taxonomy manifest 固定为：

```text
bb2b025fb26974cf06574117d8e055144d9413c81c035595458c24181f29c72e|4f9ac3595a1a6e90cb1f369593bd8fe2483ca7d5ede7dc6d5ae3c2fe469672aa|5663d8e14bb5fa6a5706828fe443a8c08ac2e62bad3e56403dd45bc6df939b29|43|13|bb2b025fb26974cf06574117d8e055144d9413c81c035595458c24181f29c72e|e3e7a77aeec447cc3035472c5f660c8675238fe260081ce9cedf4dc014b37001|16913f8503da5e27be72321a3311025bba9a6cf454f8b8b5dad9b4a09ad3417d|5949f7b630376a59c643f9024210625811606a1a41f90f4bc99ee19dfb99d38c|74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622
```

| 项目 | 固定值 |
| --- | --- |
| IAM API / event | `26ffd8243c0baa2580d21e8878897ed0f13aa61fd9ba468cca8edf1fe277477c` / `6af7e75f738bfeef9aeed0ac8e84da782485c1a42e1c937c9d51e66884bad934` |
| IAM 0043 SQL | `1e6d005858bef6f8dfbcbba2db20f4d515970fa78000b766eed55db4bc4f89df` |
| IAM manifest / combined | `7edad01ff151168e4e048848fe770eb0ea199a1034a8119658a1c3bf53205b5e` / `bb2b025fb26974cf06574117d8e055144d9413c81c035595458c24181f29c72e` |
| Demand API / event | `046561ae51d147e8df3b8fcf0b61f1dd922efe452175e63f128a937e8f11c4ff` / `46631be37cb70aea771d2103e1fe39dc39f3f4303239ae1dc6e55fa946d1059c` |
| Demand 0013 SQL | `2c4eae15aa6985474042254ce50ef71d15f9efe97bf580f45c1f3a0463857327` |
| Demand manifest / dependency | `5663d8e14bb5fa6a5706828fe443a8c08ac2e62bad3e56403dd45bc6df939b29` / `e3e7a77aeec447cc3035472c5f660c8675238fe260081ce9cedf4dc014b37001` |
| Trust / Appeal API contract | `6647e16e9f8f0ab321ed9985eb2da4e591e2217fdaa43ba663355a4f152f44b2` / `ad0fd5874ad6d3343c62334805fe51c088df7b9db9215decfda95ee90a836e46` |
| Trust 0019 SQL | `a8dc9b4ba6dbb8a4d1b2e89155745bf30fa617cdbe6fbe6c93a918f277d0c85e` |
| Trust manifest / combined | `5949f7b630376a59c643f9024210625811606a1a41f90f4bc99ee19dfb99d38c` / `16913f8503da5e27be72321a3311025bba9a6cf454f8b8b5dad9b4a09ad3417d` |
| Trust required IAM / Demand schema | `43 / 13` |
| Taxonomy manifest | `74153871acb734ad3fe7619174695af57a751b64fd0aba2165ed776ec2538622` |

当前字节 pin 冻结在 `tests/deployment/fixtures/current-head-v26/`。其中 IAM、Demand、Trust manifest
与 Trust runner pin 都是只读静态 fixture，不是运行结果。

v26 将 IAM、Demand、Trust 从 v25 的 `42 / 12 / 18` 前移到 `43 / 13 / 19`，发布审核分配主动释放、
冲突后禁止同一 reviewer 重领以及 Trust 依赖 repin；此前 privacy-safe HTTP observability 与 bounded local
Docker logging 继续作为同一静态发布的精确 byte pins：

| v26 操作契约资产 | SHA-256 |
| --- | --- |
| `platform/src/desire_platform/http/observability.py` | `49c06c6882cc2a4fdf8c00922bc77166ad65f39a7f93c0f84b6cf6e104fd99ff` |
| `platform/tests/internal_pilot/test_http_observability_red.py` | `f28bec3d399488c1fd1921210c0f0ba78b1294908d38003f1f28620b5729c59b` |
| API composition / composition test | `9215d8243d264c79fc24d4c38f221bd521d7d83d061402bc745b9d82cecf89b6` / `6a51e2d29aa11feacbbdc0fb6c4c109dced7bfb9b1fc5beff4d09bd9a83f9f4f` |
| runtime adapters / API server / server test | `9e4d9cb304fe87864d946ad8addf1cff5eefc1ecae767990529b8859eaac720b` / `9668d5fb24ef9fe1c1c6fcff19cc8e58a433461a372124b5f2e74404faac5fc2` / `62d0b29bd701ed0993cdd8cfb0ac0b38b52b432ea66832cd00e95a714dd363cb` |
| `compose.yaml` / `compose.dev.yaml` | `0ee95ec9c638ff24e1caa64a50d8088ef6834b10e9654d70ddb65a569d0b9c41` / `26794d230babeedc220da1bcbf4decd3b25fa0566ecb0699e53b136cd98b9ad1` |
| operations / real-OIDC Compose | `ef51b6a0c0163c0b46714266b2ed47394fe27077086d0ebe25e137618d96c52b` / `342f5cc9837d3452254296194e3d7aec62470acf1ea1c934e765ba14e1ef564c` |
| container verifier / local manager | `a6eb67b2f881771c26188a377fa0203a4791676e74059f68f3fcfcde9f524f9d` / `1b8bcaa66dcf26484f6d1332a89895b3d47bb74d997e49908ab463395197fad9` |
| private / real-OIDC Compose contracts | `d9b154319b0b9c094848e1f6e2732bcbf715665ce03a969f3a549f1ebee19e58` / `275af01035420b1d81c60610f18c716624dbc1e99d4c18d3b127b6e9f798e957` |
| container / private Compose tests | `d3dc09fbe1334061e21c5d2c5a5afb42b9e833dd0d8144c885c10a55c404ae7f` / `80d1b476c38ef3424ea166066a4073492de66547d7a4fd33f3fbef092c4c54b3` |
| local manager / real-OIDC / PostgreSQL operations tests | `6ab92bd2a874f84289480af43147f406b115c5cfd9aefdf73e0b71d5e2571556` / `9ef6c57da2d4379c24b489b53eeaf88cc589634ca0f0e8a6210da0df37e5620f` / `03fff4947a73a044d990a05b6d8fd6dc1c23bd38f864d71b33dc407be8185207` |
| v26 PostgreSQL backup/restore script / core facts | `48fe07e4a845738cd620b2584eae984d1a66d2258f6fc2c46b0ee63eaec2d72c` / `274cf10f533673a1541f9dd186039153605bc420f847fa14110027bd5650f153` |
| v26 PostgreSQL operations overlay / static test | `7fc79306fce5feb2d985390ab6e8f6a77955a5ad7d53bb341e25c8ed0df1e041` / `e9243aac88214db2e159e92a793e9a3044cd2b53378951a26a44e2d81e99347e` |

## OPERATIONS_REVIEWER 主动释放审核分配边界

IAM43 只把 `RELEASE_REVIEW_ASSIGNMENT` 加入既有 reviewer authority v2 关闭操作集；调用者仍须是当前
`OPERATIONS_REVIEWER` duty、当前 session 与同一 active assignment 的 reviewer。应用入口固定为
`POST /v1/app/demands/{demand_id}/review-assignments/{assignment_id}/release`，请求体精确为
`{reason_code}`，原因闭集是 `CONFLICT_DECLARED / WORKLOAD_RELEASE`。请求必须同时携带强 `If-Match`、
`Idempotency-Key` 与 CSRF；开放字段、自由文本原因、错误 Demand/assignment 绑定、旧 ETag 或失效 duty
均 fail closed。

服务在任何 ACTIVE target discovery 之前先执行 completed receipt recovery。已完成的同一命令只读恢复原响应；
同一键改换 payload、assignment、版本或 actor 被拒绝，无法证明完成或未执行则返回 unknown outcome，不盲目重试写入。
首次成功在一个事务内把 assignment 标为 `REVOKED`，写入不可变
`demand_review_assignment_releases`，提升 Demand revision，并各完成一条 receipt、audit、outbox 与
`DemandReviewAssignmentReleased` event。返回完整 Demand resource：状态仍是 `SUBMITTED`、
`review_assignment=null`，释放后队列对其他合格 reviewer immediately available；这不是通过或退回决定，也不修改
Demand 内容。

`CONFLICT_DECLARED` 的不可变事实会关闭该 same reviewer 对 same submission/version 的 list、resolve 与直接
claim 三条重领路径；`WORKLOAD_RELEASE` 则保持可由本人重新领取。新 submission 或新 Demand version 不继承旧冲突，
避免把一次利益冲突声明错误扩展成永久封禁。Web 将释放区与最终审核决定分开显示，成功响应只有在
`200 + no-store + ETag + DEMAND/SUBMITTED + null assignment` 全部闭合后才清除本地选中并刷新队列；
`412` 使用 current ETag 恢复，`503` 保留待恢复意图。

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
与 `trust_terminal_history_discoverable=true`、`terminal_history_actor_scoped=true` 验证，v26 不扩大该读取面。

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

## Privacy-safe HTTP observability 边界

共享 ASGI mux 外层只产生 `HTTP_BOUNDARY_OBSERVATION_V1`。这是 low-cardinality 的运行观察，
字段闭集只有固定 component/event type、关闭 method、`IAM / EDITOR / TRUST / APPEAL / UNMATCHED`
operation family、status class、outcome 与 monotonic latency bucket。它不记录 raw path/query/header/body，
也不接收 cookie、authorization、request/response bytes、trace ID、actor/object ID 或异常文本。

每个 HTTP scope 在 `finally` 中精确形成一条观察；非 HTTP lifespan 原样转发且不观察。未处理异常只映射为
`FAILED / NO_RESPONSE`，不反射异常内容；clock 异常或逆序只变成 `UNAVAILABLE`。observer failure 被吞掉，
不能改变已经有效的 HTTP 结果，也不能成为 Audit 来源。组合层用 `ObservedAsgiApplication` 包住完整
IAM/Editor/Trust/Appeal mux，并关闭 IAM transport 的旧重复 telemetry；Uvicorn 保持
`access_log=False`、warning level、无 server header，避免另一路径重新输出 raw request target。

静态测试精确覆盖秘密 cookie/token、opaque object ID、query 与 private response 不进入 JSON line，
五个 operation family、method/status/outcome 闭集、全部 latency 边界、未处理异常、observer failure 和
lifespan 转发。该观察只能辅助操作诊断，不证明业务 audit 完整、告警、外部汇聚、SLO 或生产监控就绪。

## Exact bounded local Docker logs 边界

base、Dev Container、PostgreSQL operations 与 real-OIDC overlay 的每个服务都必须精确使用
`driver=local`、`max-size=10m`、`max-file=3`、`compress=true`；值必须保持字符串类型，不能换成
`json-file`、放大容量、关闭压缩或加入未审核 option。Compose 静态 verifier 会遍历 base、development、
operations 的完整服务闭集；private-server 与 real-OIDC 合同对最终解析文档重复执行相同精确检查。

本地 trial manager 既校验解析后的 Compose logging，也用 `DOCKER_LOG_CONFIG` 对每个已创建容器的
Docker `HostConfig.LogConfig` 做 live inspect 复核；即使攻击者重算其他 security projection，日志配置漂移
仍 fail closed。测试覆盖缺失 logging、driver 漂移、`max-size=100m`、数值型 `max-file`、
`compress=false` 与未知 option。这个边界只限制 Docker 本机日志保留量，不等于远端日志备份、完整告警、
不可抵赖审计或生产可观测性。

## PostgreSQL 逻辑备份与隔离恢复静态入口

当前头新增 `deploy/postgres-backup-restore-v26.sh`、
`deploy/postgres-core-facts-v26.sql` 与 `deploy/postgres-operations-v26.compose.yaml`。脚本把
backup/restore 的模式门禁固定到 IAM43 / Profile3 / Demand13 / Trust19 / Taxonomy2 及本页十段契约；
overlay 只重绑脚本和 facts 两个 config，不复制或改变 service、image、command、secret、volume 或 network。
v25 脚本、facts、overlay 与静态测试保持历史字节不变。

v26 的 `iam_durable_counts` 在共享去标识摘要之外，增加 organization、external identity、contact point、
auth transaction、session family/security event、membership role、platform duty、consent grant/withdrawal、
IAM command receipt 与四类 sandbox bootstrap state 的精确行数。隔离恢复前的空目标门禁覆盖同一组运行期表，
并补上共享摘要已计数但旧门禁漏掉的 `iam.user_role_grants`。policy publication / consent-offer bootstrap
catalog，以及 schema/config migration-seeded catalog 均不纳入零行门禁。backup 前后及 restore 后 facts
必须完全一致；活跃写入会令演练
fail closed，因此必须先保持 writer quiescence。

Demand13 新增的不可变 `demand_review_assignment_releases` 同时进入恢复前 empty-target 零行门禁与
`continuity_counts` core facts。这样隔离目标若预存 release fact 会在 restore 前关闭失败，且 source/restore
对审核分配释放事实的行数漂移也会被 facts 比较发现；它仍只是去标识 count-level 证明。

这是 count-level、privacy-safe 的连续性证明，**not comprehensive field-level continuity**：它不能逐值证明
`public_name`、identity binding 或 receipt payload 等字段相等。custom-format archive 校验和、`pg_restore`
单事务成功、模式/契约复核及 facts 相等共同提供当前静态边界，但仍不能替代 PITR、加密离机备份或真实恢复演练。

未来经单独授权后，source backup 与 fresh isolated restore 只能通过 exactly `three Compose files` 的 helper：

```bash
compose_v26_operations() {
  docker compose \
    --project-name "$DESIRE_DATABASE_OPERATIONS_PROJECT" \
    --env-file "$DESIRE_DEPLOYMENT_INPUT_ROOT/compose.env" \
    -f "$PWD/compose.yaml" \
    -f "$PWD/deploy/postgres-operations.compose.yaml" \
    -f "$PWD/deploy/postgres-operations-v26.compose.yaml" \
    "$@"
}

export DESIRE_DATABASE_BACKUP_BASENAME="v26-iam43-profile3-demand13-trust19-taxonomy2-drill01"
```

source 阶段必须绑定已运行且不重建的当前 project；restore 阶段必须换成此前不存在的、满足脚本关闭命名
规则的隔离 project、隔离 internal network 与 fresh volume。helper 不得附加第四层 IPAM overlay，不得使用
`--build`、`--pull`、`run --rm`、`down` 或 `rm`。只有 retained one-shot 容器 exit 0 且日志分别精确出现
`DATABASE_BACKUP_READY` 与 `DATABASE_RESTORE_VERIFIED`，随后同一 Platform image 的 restore migration
replay 精确 skip 全部版本，才可另记动态结果。

本次仅发布并校验上述静态入口，没有调用 Docker、没有创建备份 artifact、没有创建恢复资源，也没有得到
两条成功日志。因此状态继续是 `STATIC VERIFIED / NOT PRODUCTION EXECUTED`，不是 backup/restore 动态证据。

## 只读静态校验

从仓库根运行：

```bash
python3 -B scripts/verify_current_head_v26.py
python3 -B -m unittest tests.deployment.test_current_head_v26_contract -v
python3 -B -m unittest tests.deployment.test_postgres_operations_v26 -v
```

v26 校验成功只输出 `{"status":"CURRENT_HEAD_V26_STATIC_VERIFIED"}`。校验只读取已签入文件，不调用
Docker，不运行迁移，不创建 evidence，也不把 `NOT PRODUCTION EXECUTED` 升级成动态成功。

## v25 冻结边界

[Current-head v25 静态模式头](/operations/current-head-v25.md) 继续保持
`18|42|42|3|3|12|12|18|18|2|2`。其 fixture 位于
`tests/deployment/fixtures/current-head-v25/`；v26 的 IAM43/Demand13/Trust19 与 assignment-release 声明不得
写回或冒充 v25 结果。v25 verifier、runbook、current-head contract test、IAM/Demand/Trust fixtures 与 runner pin
分别冻结为
`34a45ff42311d342cafe4d9a6abc8a7453b0012ebb6daf1685bf9bd3e0c6adea`、
`c3ddb2cf4a0ea254229cb1d0da38c462e7c0b2b4ac943b14d92594d1cf0f3881`、
`8edf618dfff911143733da477cbc5712d0d1bc570df8f00339d694aa63dd6b08`、
`9c6e0396867d68ac49260684a9531c592055d62cac20d7ebdfb578c236df025d`、
`919d62a9b32dc29619a561940f9c79e21700562a0cdd9ef7e9f13a40cea43345`、
`0b7028c75c8f137bc4a55a76fe73ea956d0c5ada13031f80794b77c1c9535e19`、
`91b0381051753738e045ff6c019fb30757adfcf588bf3c45bc336c56c74678d0`。
v25 operations script、facts、overlay 与 test 另冻结为
`9aa84d3f7d37704e181a314db873e16fecfad6d770dbc1d12fbb76180d69d1bb`、
`0845ec9025efdfc208bab24b1ce3b8f56a8e2e44613eae249a00af349802507e`、
`a98b80de17604349362b813d1224a4f71d886b2d1282f9cbb944cd3b714628a4`、
`5296e02cf37a5ffdf54603639202e6f074138706832d811355ded15efe3da383`。
所有已经单独记录的 v25 dynamic evidence 都是冻结历史，不能重标为 v26 动态执行；v26 仍是
`STATIC VERIFIED / NOT PRODUCTION EXECUTED`，不构成生产授权。

```json
{"current_head_v26":{"claim":"STATIC_ONLY","execution":"NOT_PRODUCTION_EXECUTED"},"overall_status":"BLOCKED","production_authorized":false}
```

<!-- END CURRENT_HEAD_V26_CONTRACT -->

与本静态合同分开记账的 checkout runtime/source 本地合成验收见
[冻结的 v25 本地 INTERNAL_SANDBOX 试用记录](/operations/local-internal-sandbox-trial.md#historical-v25-checkout-local-synthetic-dynamic-acceptance2026-08-26)。
该历史记录不改变本页的 `STATIC VERIFIED / NOT PRODUCTION EXECUTED`、`overall_status=BLOCKED` 或
`production_authorized=false`。

本页成为 current schema pointer 不构成运行授权；任何迁移或部署仍须单独批准并使用独立的新版本运行资产。
