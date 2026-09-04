# 本机 Docker 工作流程验收（2026-09-04）

状态：**当前已实现范围的本机 Docker 功能与持久化验收通过**。当前项目为
`desire-workflow-20260904-verified`，覆盖启动、十账号核心、受邀开户、Matching 四分支、重启与
会话权限边界。浏览器仅完成下文列明的抽查；这不是完整产品、全角色 UI 或无障碍验收通过。
真实 HTTP、数据库、浏览器及前两套环境的失败证据分别记录。

## 环境与范围

- 原合成验收项目为 `desire-workflow-20260904`。下文标为原项目的核心 HTTP、重启和十账号 UI
  证据来自此项目；其错误邀请已发布为 SENT v2，但冻结快照不符合时间格式契约，保留原快照与摘要作为失败证据。
- 第二个合成项目 `desire-workflow-20260904-fixed` 采用 Matching8 的未来快照生成修复，
  复用用户已信任的精确 TLS 叶证书；十账号核心 HTTP 已通过，Matching 完成任务最终失败。
  原验收项目已停止并保留全部数据卷，不改写旧数据；更早的 `desire-supply-local` 也保留。
- 原项目有六个常驻服务：PostgreSQL 18、API、Web、Matching runtime、合成 OIDC、HTTPS edge；
  五个初始化任务全部退出 0，只有 edge 发布 `127.0.0.1:443`。第二个 `-fixed` 项目启动时同样六服务
  Healthy、五项初始化 exit 0，使用新镜像从 Matching1–8 创建数据库；其核心 HTTP journey 已通过。
- `-fixed` TLS 的三个文件通过 Docker 精确复制并逐字节校验一致，未再次修改宿主信任。其证据目录
  为 `.local/workflow-evidence-20260904-fixed/`，不覆盖原项目证据。
- Matching 完成任务失败后，`-fixed` 中遗留的 OPEN attempt 会被后续审核队列优先领取，且当前没有
  可用于恢复该失败 job 的合法 redrive 入口。Matching9 全流程 PG 回归通过后，已创建干净
  `desire-workflow-20260904-verified`；2026-09-04 09:01 UTC 六服务 Healthy、五项初始化 exit 0。
  `-fixed` 保留为第二套失败证据，不用改 SQL 或直接改业务状态恢复旧任务。
- 当前项目最终检查为六个业务服务与文档服务共七项 Healthy；只发布 `127.0.0.1:443` 和
  `127.0.0.1:5174`，主页与 OIDC 检查通过。最终镜像与模式头记录于 `environment.json`，
  服务状态记录于 `final-service-health.txt`；IAB 已打开文档并确认当前管理项目为 `-verified`。
- 开发与回归使用独立 `desire-supply-local-dev` 数据库，不在业务库执行破坏性测试。
- 业务运行、构建、依赖、数据库与验收 runner 均在 Docker 内执行；少数只读仓库静态 verifier
  使用 macOS 自带 python3 调用宿主 Docker CLI，未在宿主安装项目依赖。
- 仅使用合成身份和业务数据；资金确认为零值合成事实，不涉及实际付款或合同。

## 当前 `-verified` 项目复验结果

本节只属于 `desire-workflow-20260904-verified`，证据目录为
`.local/workflow-evidence-20260904-verified/`。已读取其新的 `journey-result.json`，状态为
`TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，不复用 `-fixed` 的业务结果。

| 范围 | 当前项目实际结果 | 证据 |
| --- | --- | --- |
| 启动 | 六个常驻服务 Healthy，五项初始化 exit 0，Matching9 新镜像 | 主任务启动记录 |
| 十账号核心协作 | 各自 OIDC/workspace/职责正确；Profile ACTIVE v3、Demand 整改重提后 FUNDED v15；Trust 独立解除、Appeal 决定和回执、Finance 双席及历史隔离、组织/账号管理通过 | `journey-result.json` |
| 未预置需求方受邀开户 | `PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN`；待激活身份无职责/成员/workspace，邀请与政策接受后仅目标组织 DEMAND_OWNER；新需求创建/取消、精确重放与版本历史通过 | `invited-owner-result.json` |
| Matching 四分支 HTTP | `MATCHING_HTTP_E2E_GREEN`：SELECTED → MATCHED / SELECTED / ACCEPTED；DECLINED 与 WITHDRAWN → NO_MATCH / CLOSED_NO_SELECTION；ZERO → NO_MATCH（无分配）。人工分支命令精确重放、原 Session exact-ID 终态 200、活动列表为空与旧 by-attempt 404 通过 | `matching-http-result.json` |
| Matching 独立数据库核对 | `MATCHING_DATABASE_BEFORE_RESTART_GREEN`：4 个分支各 18 项检查全部为 true；每条生命周期仅一份 request/attempt/run/selection，delivery/worker/completion 完成且无重试；零候选实际 SYSTEM_CLOSE 到 CLOSED_NO_SELECTION | `matching-database-before-restart.json` |
| 当前项目浏览器 | fresh OIDC 登录 Creator，无证书提示；整栈重启及最终 Web 部署后，同浏览器 Session 仍有效，Profile ACTIVE v7 和三条邀请保持。逐条打开 ACCEPTED v3、DECLINED v3、WITHDRAWN v4 详情，安全披露完整；ACCEPTED 显示“已接受”，后两者三个响应命令均禁用；1280px 桌面截图布局正常，无 UI 写入 | `browser-matching-observations.json` |
| Matching 重启后 HTTP | `MATCHING_HTTP_RESTART_GREEN`：五个原 Session 恢复，四分支 Demand 不变，原 Session 三条终态 Selection 读取成功；新 Owner Session 对同三个已知 ID 均 404，四个活动列表为空、Profile ACTIVE；测试 cookie 检查点已删除 | `matching-http-restart-result.json` |
| 核心重启后 HTTP | `TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN`：停栈前 Profile 基线 ACTIVE v7、核心 Demand FUNDED v15 与 Finance/Trust/Appeal/组织历史保持，队列和活动分配符合终态 | `restart-result.json` |
| Matching 重启后数据库 | `MATCHING_DATABASE_RESTART_GREEN`：四分支各 18 项检查继续通过，九组业务状态与重启前逐值相等，仅排除快照捕获时间 | `matching-database-restart-comparison.json` |
| 初始化任务未重跑 | 前后记录逐字节相同，容器 ID、开始/结束时间与退出状态未变化 | `jobs-before-restart.txt`、`jobs-after-restart.txt` |

## 第二个 `-fixed` 项目复验结果

本节仅属于 `desire-workflow-20260904-fixed`，结果位于 `.local/workflow-evidence-20260904-fixed/`。
已读取新的 `journey-result.json`，状态为 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`。

| 范围 | 新项目实际结果 | 证据 |
| --- | --- | --- |
| 十账号 OIDC、工作区、职责与政策 | 通过；十账号职责与各自 workspace 符合预置范围 | `journey-result.json` |
| Profile、Demand 整改重提与审核 | Profile ACTIVE v3；Demand 整改重提后 FUNDED v15，审核 VERIFIED | `journey-result.json` |
| Trust 与 Appeal | 阻断期验证返回 403 且公开投影不变；第二人独立解除；申诉 VACATE_AND_REMAND，领取/释放/重领/决定回执与安全历史读取通过 | `journey-result.json` |
| Finance | 异常 cycle、释放重领、两份独立确认、本人历史隔离通过；最终 SECURED / FUNDED | `journey-result.json` |
| 组织与账号管理 | 邀请接受/撤销、成员暂停/恢复/撤销、临时职责授予/恢复、自身保护与会话撤销通过 | `journey-result.json` |
| Matching 完整分支 | 新邀请 CREATE/PUBLISH 与精确重放成功，随后 HTTP ACCEPT；IAB 已读取 SENT v2 与 ACCEPTED v3。Trust 时间参考点修复后，coordinator 完成 SQL 又返回 P0002；原 job 最终失败，此项目四分支未完成。后续 `-verified` 的成功不改变此失败结论 | `matching-selected-coordinator-blocker.json` |
| 新项目浏览器复验 | Creator 原浏览器 Session 读 SENT v2；HTTP ACCEPT 后再次刷新并点开 ACCEPTED v3，接受/拒绝禁用、撤回启用。390px/320px 邀请页与 sticky header 截图无横向溢出，documentWidth 等于 innerWidth；未通过 UI 写入 | 主任务实际 CUA 观察 |
| `-fixed` 重启 | 未执行，后续验收已转 `-verified`；不移用原项目证据 | 无此项通过证据 |

这些结果来自真实 HTTP runner，不表示在新项目重新完成了十角色浏览器点按。

## 原项目已执行的协作验收

本节全部属于 `desire-workflow-20260904`，不得当作新 `-fixed` 项目的执行结果。

| 范围 | 实际结果 | 证据文件 |
| --- | --- | --- |
| 十账号 OIDC、工作区与政策 | 通过 | `journey-result.json` |
| Creator Profile 保存、发布 | 通过 | `journey-result.json` |
| Owner 提交、Operations 整改、Owner 重提、Operations 验证 | 通过 | `journey-result.json` |
| Trust 报告、保护阻断验证、第二人独立解除 | 通过 | `journey-result.json` |
| Owner 申诉、Appeal Reviewer 领取/释放/重领/决定及历史 | 通过 | `journey-result.json` |
| Finance 异常 cycle、释放重领、双人确认、本人历史隔离 | 通过 | `journey-result.json` |
| Access Admin 职责授予/撤销、账号停用/恢复、撤销会话 | 通过 | `journey-result.json` |
| Org Admin 邀请、名称、成员暂停/恢复/撤销 | 通过 | `journey-result.json` |
| 未预置需求方账号：受邀开户、精确组织/职责、创建并取消需求 | 通过 | `invited-owner-result.json` |
| 完整 stop/up 后重读需求、资金、Trust、Appeal、组织历史 | 通过 | `restart-result.json` |
| 有效 cookie/CSRF 跨重启；已撤销 cookie 不复活 | 修复后通过 | `session-before-restart.json`、`session-after-restart.json` |
| 初始化任务未重跑 | 前后容器 ID、开始/结束时间、退出码完全相同 | `jobs-before-restart.txt`、`jobs-after-restart.txt` |
| 草稿精确重放、409、412、显式合并、版本不变与隐私 | 修复镜像真实 HTTP 复验通过：`EDITOR_CONCURRENCY_PRIVACY_E2E_GREEN` | `editor-result.json` |
| FUNDED→SYSTEM RequestMatching 入口 | 独立 exact-target CLI、Docker wrapper 与凭据准备已实现；本机凭据 provision 正常 | 聚焦回归及主任务执行记录 |
| Matching 邀约、接受/拒绝/撤回、选择/关闭、零候选 | 审核与 Selector 领取成功；Matching7 恢复后发布与精确重放均 HTTP 200，唯一邀请 SENT v2、PUBLISH receipt COMPLETED。Creator 列表和详情因冻结披露时间为 `+00:00` 而返回 503，完整 Matching 未通过；旧快照未修写，后续转新项目复验 | `run_internal_sandbox_matching_e2e.py` 与迁移、只读数据库诊断记录 |
| 真实浏览器角色协作、桌面与窄屏 | 十个预置账号均已登录并读取工作台；Creator 实际保存/发布，指定桌面页面和 Access Admin 窄屏页头已复验 | [UI 矩阵](local-workflow-ui-acceptance-2026-09-04.md) |

结果文件位于仓库忽略目录 `.local/workflow-evidence-20260904/`。结果不含 cookie、CSRF、OIDC
授权参数、邀请秘密。会话重启检查使用的临时 cookie checkpoint 已在完成后删除。

## 原项目已执行的浏览器检查

用户亲自完成两个 hosts 映射与本次精确叶证书的 SSL 信任后，主任务使用 CUA 控制 IAB 进入工作台。
以下浏览器证据均属于原项目，独立于 HTTP runner；历史重读不表示同一业务写入也已通过网页重新执行。

| 角色 / 页面 | 本次实际观察或操作 |
| --- | --- |
| Creator | 登录后将每周可用时间改为 21 小时，保存到 v6，再发布到 v7；邀请 CREATED 时新 Session 刷新显示服务端验证的 0 项，未发布邀请未提前披露。发布后刷新显示 SERVICE_UNAVAILABLE 并保留旧 0 项，不能将旧列表当作当前服务端空结果 |
| Demand Owner | 读到核心需求 FUNDED v15、三个不可变版本、NEEDS_CHANGES / VERIFIED / DISCREPANCY 历史，以及 `/scope` 版本差异 |
| Operations Reviewer | 读到本人四条完成历史；Matching Review 队列为空 |
| Finance Operator 01、02 | 分别重读本人双人资金确认历史 |
| Trust Officer 01 | 读到本人一条完成案件；当前队列为空 |
| Trust Officer 02 | 确认 TRUST_OFFICER 职责；本人完成案件、活动案件、高风险复核均为 0；未写入 |
| Appeal Reviewer | 本人完成历史一条；点击 VACATE_AND_REMAND 后 fresh 读取终态、PROCEDURAL_ERROR → VACATE_AND_REMAND 与结构化评估；受限正文不在 DOM |
| Org Admin | 确认 ORG_ADMIN 职责；组织名称 Updated、四名成员、五条邀请含 ACCEPTED / REVOKED；本人暂停/撤销禁用 |
| Access Admin | 确认 ACCESS_ADMIN 职责；十个预置账号；点开 Creator 读取 current v6，仅授予 CREATOR，其余职责未授予 |
| 原项目 Matching 后续交互 | 原项目未完成；其失败证据保留，后续结果属于另一个项目 |

十个预置账号均有真实 UI 登录与工作台读取证据。只有 Creator 在本轮执行了浏览器业务写入；
其他角色的业务写入通过 HTTP runner 验证。1440px Creator 与 1280px Access Admin 桌面截图布局
正常。分开调整 viewport 和截图后，390px 截图比例恢复正常，并发现长账号名覆盖页头按钮的问题。
CSS 修复部署后，Access Admin 的 390px / 320px 实际截图中账号信息不再覆盖刷新/退出按钮，且
documentWidth 等于 innerWidth；320px 标签分两行，账号与会话号正常省略。这只证明这些具体页面
和页头区域的视觉结果，全部角色的响应式、键盘、焦点和移动交互仍未完成系统检查。

## 发现的真实缺陷

1. 显式撤销当前 Session 后误调用旧 generation replay 程序，返回 503。现改为 401；旧 generation
   的安全收敛机制保持有效。单元、真实 PG18、HTTP 和原 cookie 跨重启检查通过。
2. PostgreSQL 编辑器在检查精确重放之前检查 ETag/草稿状态，导致已成功请求重试返回 412/404。
   修复 Profile 保存/发布与 Demand 保存/提交；新请求的权限、OCC、状态和合法选项检查仍执行。
   `editor-result.json` 已确认精确重放、改 payload 409、旧版本 412、显式合并和隐私检查全部通过。
3. OIDC chooser 的 `form-action 'self'` 阻止表单提交后的跨源回调。只将项目两个固定 HTTPS origin
   加入 form-action；不增加通配、脚本权限或动态请求提供的 origin。
4. 运行中的系统原先没有把 FUNDED 推进到已设计的 RequestMatching 命令。现已加入操作员显式
   指定对象的 SYSTEM CLI，保留正式规则、Trust hold 与回执边界，并使用独立凭据容器。
5. Matching3 的 ingest SQL 变量歧义返回 42702。新增 Matching4 正式迁移修复后，实际 ingest 与
   run 已推进；随后发现 coordinator 领取 job 后仍保留 CLAIM scope，RLS 阻断 attempt 与关闭意图
   读取，并暴露首次 claim 审计版本 0 的约束错误。Matching5 已修复并通过独立 PG 的 SYSTEM_CLOSE
   终态与 CHOOSE/CLOSE 领取/重放回归；最终完整 HTTP 结果另见 `-verified`。历史 Matching1–3 与已应用
   Matching4 均未改写。
6. 窄屏页头的 identity-summary 继承 baseline 对齐，长账号名覆盖刷新/退出按钮。修复移动 grid
   最小宽度、拉伸对齐与子项最大宽度后，已部署并完成 Access Admin 390px / 320px 实际截图复验。
7. 审核领取返回 503 `COMMAND_OUTCOME_UNKNOWN` 的直接原因是 `SecureRuntimeSources` 的封闭
   ID 用途登记缺少 Matching 运行时所需名称，数据库尚未写入 assignment 或 receipt。已精确补入
   八类用途和 outbox 序号 0–101，保留未知用途拒绝；使用真实 SecureRuntimeSources 的桥接回归
   已通过，覆盖领取、创建、发布与失效。
8. 与上述 503 独立，固定 reviewer claim 函数在 targetless CLAIM 下看不到 result，且缺少 attempt/run
   的行锁 policy。Matching6 新增三条固定 definer policy，保留 runtime 无直接表权限和行锁
   `WITH CHECK(false)`；最终 SQL 已完成只读权限边界复核，22 项静态与真实 PG 回归通过并已正式迁移。
   错误 scope/operation/预设组织均被拒绝且不产生回执，直接结果/候选/输入读取与 definer 普通 UPDATE
   均返回 42501；固定 claim 可处理真实 eligible run 并精确重放。
9. Matching6 部署后的真实 HTTP 创建邀请首请求返回 201，二次同 key 返回 409：前置 prepare
   先于已有成功回执检查。Matching7 已加入精确安全回执
   probe，运行时保留当前认证与分配检查，再恢复已完成回执；新请求继续 prepare/Trust 检查。
   prepare/Trust 与并发首请求提交之间的窗口也会重新检查当前分配，并只读恢复同一请求的回执，
   不重试创建写入。PG 与桥接回归已通过；原项目后续发布与发布重放均已返回 200。
10. 发布后 Creator 列表和详情均返回 503。数据库只读确认唯一邀请 SENT v2 与已完成 PUBLISH 回执，
    正式 Creator list/detail 函数均返回一份对象，未发生 SQL 错误；失败发生在 Python HTTP 投影校验。
    冻结披露的 `expires_at` 实际为 `2026-09-06T07:42:12+00:00`，而 v1 契约与校验要求 `Z`。
    Docker 已复现 adapter 接受该 UTC 偏移、HTTP 拒绝。已冻结快照和摘要不改写，也不放宽 v1；
    Matching8 已修正未来生成并增加创建前严格校验；`-fixed` 证实该问题恢复，但后来出现独立的完成
    任务缺陷，最终完整流程由 `-verified` 验证。
11. 新 `-fixed` 项目另有 Web/BFF 缺陷：冻结披露为 `2026-09-06T08:17:43.000000Z`，外层同一到期
    时间为 `2026-09-06T08:17:43Z`，Web 原先按字符串判定不一致，返回 `MATCHING_BACKEND_UNAVAILABLE`。
    新比较只在比较键中删除小数末尾零，不修改原始快照、响应或摘要，也不使用会丢失微秒的 Date.parse
    值作相等判断；相差一微秒或一纳秒仍拒绝。创建响应与提交到期时间的绑定同样修复。
    三个新增回归先复现失败，修复后 Matching contract/UI 25 项及 TypeScript 检查通过；新 Web
    部署后 IAB 已实际恢复一条 SENT 列表与 v2 详情。此问题独立于原项目不符合 `Z` 契约的坏快照。
12. 新项目 CHOOSE 首次完成时，把正常 Trust 决策的评估时间与调用前记录的本地时间比较，误判为
    未来证据。实际只读核查为 ALLOW、有效期 15 秒；Python 时间参考点修复已部署并成功越过此检查。
13. 随后 coordinator 的 `complete_selection_v1` 完成 SQL 返回 P0002：当前 COMPLETE_SELECTION
    操作看不到它需要验证的原 USER 选择回执。Matching9 已以精确只读 policy 前向修复，Matching1–8
    原字节冻结。最终原 job 为 FAILED、attempt_count 3、fencing_generation 4、LEASE_EXHAUSTED；
    HTTP 选择仍 PENDING_CHOICE，数据库 selection/attempt 为 OPEN、Demand 为 MATCHING。
    原失败任务不能通过当前合法入口 redrive，也未新 key 重发选择、改 counter 或换 intent；遗留
    OPEN attempt 还会占据后续审核领取队列。证据为 `matching-selected-coordinator-blocker.json`。
    Matching9 的新数据验证已在干净 `-verified` 项目通过四分支 HTTP 与逐条数据库核对，不把新数据
    成功记作旧任务已恢复。

## 自动化回归记录

以下为阶段性分组，存在重叠，不应相加当作独立用例总数：

- Platform 当前工作台、Matching、LOCAL_SYNTHETIC、指定 PG18 gate：462 passed。
- MVP CLI、导入、校验、匹配、报告等：134 passed。
- Web 构建与现有测试：239 passed；TypeScript 与 lint 通过。
- Session 修复聚焦回归：33 passed。
- PostgreSQL 编辑器相关回归：86 passed；补充状态/权限检查的两个 PG 用例也通过。
- Synthetic OIDC CSP 回归：24 passed。
- SYSTEM Matching workflow 聚焦回归：9 passed。
- Matching HTTP 聚焦回归：26 passed。
- 本机 Docker wrapper 聚焦回归：9 passed。
- 独立 SYSTEM 凭据 prepare 单元回归：9 passed；随后本机真实 provision 正常。
- Matching4 静态与真实 PostgreSQL 迁移回归：19 passed；不代表 Matching5 或完整业务终态通过。
- Matching5 静态与真实 PostgreSQL 迁移回归：20 passed，含 SYSTEM_CLOSE 实际 NO_MATCH、
  CHOOSE/CLOSE 领取/重放及错误 workload/marker 拒绝；不代表完整 HTTP/浏览器协作通过。
- SecureRuntimeSources 的 Matching ID 用途桥接回归：19 passed；不等于真实 PG 或完整 HTTP 通过。
- Matching6 静态与真实 PostgreSQL 回归：22 passed，含真实领取/重放和上述权限负向检查；正式迁移
  仅应用 6，其余版本 skip，见 `matching6-migration-result.json`。
- Matching7 静态与真实 PostgreSQL 回归：22 passed；真实 CREATE 与原回执恢复没有重复事实，
  changed payload/version 为 409，错误 marker/session 与过期分配为 404，错误 scope 被拒绝。
- M7 Python 桥接最新回归：15 passed，含并发窗口有/无回执两例。此前 RuntimeAdapters 与 M7 桥接
  的联合分组为 20 passed；这些阶段分组重叠，不相加。
- Matching8 静态与真实 PostgreSQL 回归：23 passed，含非 UTC 会话下保留微秒的 UTC-Z 生成，
  以及真实 prepare/CREATE/publish 后 Creator list/detail 经原 HTTP 闭合投影和 canonical hash 校验。
- Matching9 静态与真实 PostgreSQL 回归：24 passed，包含真实 CHOOSE/CLOSE 完成、完成回执重放、
  原 Session exact-ID 终态读取。错误 org/selection/workload/marker/scope/operation 均看不到目标回执，
  runtime 直接读取回执返回 42501；此证据不表示 `-fixed` 已耗尽租约的 job 已恢复。
- 严格创建前时间校验及相关领域/桥接回归：43 passed；带偏移、无时区、小写 z、非法日期与非字符串
  均在创建前拒绝，合法 Z 原文与摘要不变。
- Web/BFF 到期时间绑定修复：Matching contract/UI 25 passed、TypeScript 通过；三项新增用例此前
  实际失败，覆盖列表/详情/创建响应及微秒、纳秒不等值拒绝。部署后 Creator 列表/详情另有真实
  IAB 恢复证据，不把这组自动化本身当作浏览器证据。
- Matching6 对齐时的 CI 指针、发布包与历史证据边界部署测试：251 passed，v28 只读 verifier 返回
  `CURRENT_HEAD_V28_STATIC_VERIFIED`，见 `v28-matching6-deployment-focused.xml`。v28 仍为本轮未发布
  候选；随后 Matching7 最终值对齐的同组 251 项也已通过，见 `v28-matching7-deployment-focused.xml`，
  只读 verifier 同样通过。上述证据保留各自阶段，不冒充后续版本结果。
- Matching8 对齐后的同组部署测试：251 passed；v28 只读 verifier 返回
  `CURRENT_HEAD_V28_STATIC_VERIFIED`。新证据为
  `.local/workflow-evidence-20260904-fixed/v28-matching8-deployment-focused.xml`。v28 仍是本轮未发布
  候选；v27 冻结资产和 Matching1–7 原字节检查通过，不代表新项目业务终态已验收。
- 新项目 Compose/runtime 配置只读 verifier 返回 `status: OK`；属于部署配置检查，不替代业务终态。
- Matching9 对齐后的同组部署测试：251 passed；v28 只读 verifier 返回
  `CURRENT_HEAD_V28_STATIC_VERIFIED`，证据为
  `.local/workflow-evidence-20260904-verified/v28-matching9-deployment-focused.xml`。v28 继续作为同一份
  未发布候选，Matching1–8 与 v27 冻结字节检查通过；新项目运行与 HTTP 结果见上方当前项目复验结果。

Web 的源码/纯函数/SSR 测试不能证明浏览器交互或视觉布局，详见 UI 矩阵。
本次功能验收以真实 HTTP、PostgreSQL 回归与十角色 UI 登录/工作台读取相互补充；UI 矩阵保留的
完整点按、键盘和触摸计划不属于已经执行的证据，也不改变下文明确记录的功能范围。

## 当前实现边界

当前 PostgreSQL 工作台尚无完整 Project、Agreement、里程碑交付/验收、真实 Payment 或数据权利
工作台。独立 SQLite `LOCAL_SYNTHETIC` 的七 persona、25 个动作与 J01–J12 制度回归在 Docker 中
通过，但不能用来宣称上述 PostgreSQL 产品功能已实现。

已耗尽租约的 Selection completion job 尚无正式 redrive API，遗留 OPEN attempt 可能继续占据
审核领取队列。本次没有改业务行、重置 counter 或换 key/intent 恢复失败任务；旧失败环境保留，
通过新干净合成项目验收修复后的正常流程。此运维恢复缺口不因成功路径通过而消失。

当前 Profile5 的地区输入只提供国家 root。Demand 若直接输入 CN-SH、CN-ZJ 等细粒度限制，
现有组合会按 `LOCATION_RESTRICTION` 保守排除；尚未支持这种细粒度地区组合，不能把限制自动
降为 CN 并扩成全国。当前 UI 与本次实际数据均使用 CN，因此这一局限不影响已列出的本轮路径。

## 管理本次环境

```bash
export DESIRE_LOCAL_PROJECT=desire-workflow-20260904-verified
./scripts/docker-local.sh status
./scripts/docker-local.sh stop
./scripts/docker-local.sh up
```

这些命令针对当前 `-verified` 项目；Matching 数据库对照与重启已通过。前两项目保留各自
失败证据，勿同时启动争用本机 443。不要把新环境的通过结果回写为旧坏快照或失败任务已修复。

本次浏览器测试中，用户明确授权并亲自添加了两个本机 hosts 映射，之后亲自将本次叶证书加入
登录钥匙串用于 SSL；未安装根 CA。日常独立 Chrome 入口仍可按[本机 Docker 指南](docker-local.md)
使用自身域名映射与精确 SPKI 允许项。
