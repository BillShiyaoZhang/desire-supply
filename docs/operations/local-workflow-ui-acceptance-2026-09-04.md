# 本机 Docker 工作流 UI 验收记录（2026-09-04）

状态：**所列浏览器抽查已完成，覆盖范围有限**。当前已实现功能的真实 HTTP、PostgreSQL 与重启验收
通过；浏览器记录不能扩大为完整角色交互、全角色窄屏或无障碍验收通过。
主任务在原项目完成十个预置账号登录和工作台读取，以及 Creator 编辑发布。
这些既有浏览器证据均来自原合成环境 `desire-workflow-20260904`。新干净环境
`desire-workflow-20260904-fixed` 已六服务 Healthy、五项初始化 exit 0，Creator 已实际重新登录。
新 BFF 时间绑定修复部署后，SENT v2 与 ACCEPTED v3 列表及详情已在 IAB 读取；该项目后续完成任务失败。
各环境不得混记。原项目已停止并保留全部数据卷。
Matching9 全流程 PG 回归已通过，第三个干净项目 `desire-workflow-20260904-verified` 已启动：
09:01 UTC 六服务 Healthy、五项初始化 exit 0，十账号核心与 Matching 四分支 HTTP/数据库核对已通过。
它是当前管理项目，Creator 已 fresh 登录，并在整栈重启和最终 Web 部署后读取邀请列表及三条详情；
各项目截图仍独立记账。

## 当前已确认的入口条件与实际结果

- 用户亲自在 macOS 添加 `pilot.example.test`、`identity.example.test` 到 `127.0.0.1` 的 hosts
  映射，并将本次精确叶证书加入登录钥匙串用于 SSL 信任；未安装根 CA。
- 主任务通过 CUA 控制 Codex In-app Browser，已正常进入 HTTPS 工作台并完成 Creator 登录。
  先前的证书交接已完成，当前不再以浏览器入口不可用作为阻断。

### 原项目 `desire-workflow-20260904`

- Creator 实际将每周可用时间改为 21 小时，保存到 v6，随后发布到 v7。
- Matching 邀请 CREATE 成功、仍为 CREATED v1 且未发布时，Creator 新 Session 在 IAB 点击
  “刷新邀请”，fresh DOM 显示“本页共 0 项 / 当前账号没有业务邀请（服务端已验证）”；未发布
  邀请未提前披露。随后发布成功后再次刷新，页面显示 `SERVICE_UNAVAILABLE` 并保留旧 0 项；
  这不是发布后列表为空的验证结果，详情与响应未通过。
- 其余九个预置账号均已分别登录，重读下表列出的本人业务事实；这些角色未在本轮通过浏览器
  写入业务事实，其写入证据来自独立 HTTP runner。
- 1440px Creator 与 1280px Access Admin 桌面截图布局正常。分开调整 viewport 与截图后，原先
  390px 截图比例异常消失；实际截图发现页头账号名覆盖按钮，修复部署后已复验 Access Admin
  390px / 320px 页头不再遮挡，documentWidth 等于 innerWidth。
- 原项目 Matching6 部署后，真实 HTTP 的审核与 Selector 领取成功；创建邀请首请求 201、同 key
  重放 409。Matching7 恢复后发布及精确重放均返回 200，唯一邀请 SENT v2；随后 Creator 读取 503
  已定位为冻结披露 `expires_at` 的 `+00:00` 格式与 v1 的 `Z` 要求冲突。旧快照、摘要与失败证据
  保留，不改写、不新增兼容契约。Matching8 修复未来生成，该问题在 `-fixed` 获得恢复证据；
  最终完整流程则由后来的 `-verified` 验证。

### 第二个项目 `desire-workflow-20260904-fixed`

- 新项目复用用户已信任的精确 TLS 叶证书，三个文件在 Docker 中复制并验证字节一致，未再次修改
  宿主信任；原项目已停止保留。新环境证据写入独立 `-fixed` 目录；
  以上 HTTP 与 PG 结果不属于浏览器点按证据，不能记录完整匹配协作通过。
- `-fixed` 的 `journey-result.json` 已确认 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN`，覆盖十账号核心
  Profile/Demand 整改重提、Trust 独立解除、Appeal、Finance 双席与组织/账号管理。其 Matching 完成
  任务后来失败；HTTP 结果不移作下面十账号 UI 矩阵的浏览器证据。
- 新项目 fresh IAB 中 Creator 已登录成功并读取 Profile v5。Matching 列表曾显示
  `MATCHING_BACKEND_UNAVAILABLE`；其直接原因是 Web 将合法的 `.000000Z` 与同一时刻的 `Z`
  文本误判为不等。精确小数比较修复已通过 25 项 contract/UI 测试和 TypeScript 检查；不修改披露
  文本或摘要，也不接受相差一微秒/纳秒的值。
- 修复部署后，同一个 Creator 浏览器 Session 在新标签页实际读到 SENT 列表一项；点击详情后
  成功显示 v2、安全披露各字段，接受/拒绝启用、撤回禁用。本次仅重读，没有 UI 业务写入；此证据
  已确认 BFF 时间比较故障恢复，不能据此宣称完整邀请响应、选择或关闭浏览器旅程通过。
- HTTP runner 接受邀请后，Creator 再次刷新列表并点开详情，实际读到 ACCEPTED v3；接受/拒绝
  禁用，撤回启用。接受动作由 HTTP 执行，此处只计浏览器 fresh 读取和按钮状态验证。
- 新项目邀请页在 390×844、320×844 下的实际截图中邀请与 sticky header 无横向溢出，
  documentWidth 等于 innerWidth；viewport 已恢复。仅覆盖该页面和区域，不扩大为全部角色窄屏通过。

本表依据主任务的实际 CUA 观察更新。HTTP runner、接口响应、服务健康检查和静态测试继续单列，
不能替代网页点按和视觉证据。

### 当前项目 `desire-workflow-20260904-verified`

当前 `journey-result.json` 的 `TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN` 已覆盖十账号核心协作，
受邀需求方开户与 Matching 四分支 HTTP 也已通过（`matching-http-result.json` 为
`MATCHING_HTTP_E2E_GREEN`）；数据库 4 个分支各 18 项检查均通过，重启后九组业务状态与之前完全相同。

重启后的 Matching HTTP 已另获 `MATCHING_HTTP_RESTART_GREEN`：五个原 Session 恢复，原 Session
读取三条终态 Selection 成功，新 Owner Session 对同三个已知 ID 均为 404，四个活动列表为空。
核心重启检查也通过，测试 cookie 检查点已删除；这些 HTTP 检查不代替浏览器操作。

当前实际 IAB 记录：fresh OIDC 登录 Creator 成功，无证书提示。整栈重启与最终 Web 部署后，
同一个 Creator 浏览器 Session 仍有效，Profile ACTIVE v7 与三条邀请保持；逐条点击成功读取
ACCEPTED v3、DECLINED v3、WITHDRAWN v4 详情，安全披露完整。ACCEPTED 文案已实际确认显示
“已接受”；DECLINED 与 WITHDRAWN 的接受/拒绝/撤回三个响应命令均禁用。

最终 1280px 桌面截图布局正常，viewport 临时设置已恢复，没有 UI 业务写入。公开观察记录位于
`.local/workflow-evidence-20260904-verified/browser-matching-observations.json`。本次未重新覆盖移动端
或其余角色；不能将上面 `-fixed` 的 SENT/ACCEPTED 读取、窄屏截图或最初项目的十角色登录直接当作
当前项目已重新点按。IAB 另已打开本机 Docker 文档，确认页面使用当前 `-verified` 管理项目。

## 当前产品范围

当前 `web/app/product-client.tsx` 装配了 Profile、Demand、Operations Review、Finance Funding、
账号管理、组织管理、Trust、Appeal、Sessions、Matching Recipient/Selector 与 Matching Review。
十个固定账号覆盖八个职责；Candidate Selector 和 Matching Reviewer 是当前账号在具体对象上
领取的分配，不是增加两个可任意切换的浏览器身份。

旧的七角色 SQLite `J01..J12` ADR 描述的合同签署、里程碑交付、独立验收/受益者成果确认与付款
不是当前 Web 的同等已实现入口。当前 Matching 页面明确区分接受邀请、选择意图和后续
Project/Agreement；不能将邀请接受当作签约，或将零资金合成确认当作付款。

当前 UI 的地区项与本次实际数据均使用国家级 CN。Profile5 与 Demand 细粒度地区限制的组合尚未
支持；若直接使用 CN-SH、CN-ZJ，匹配会按 LOCATION_RESTRICTION 保守排除，不能自动扩大为全国。

## 原项目十账号与分配验收矩阵

每项均须使用独立 cookie/storage。桌面建议 1440×1000，移动建议 390×844；关键窄屏状态补查
320×768。`PARTIAL` 只代表该行明确记录的操作或重读，不能表示整行计划全部通过。

| 账号 / 职责 | 正向旅程与应见结果 | 必查限制 / 错误 | 浏览器状态 |
| --- | --- | --- | --- |
| `creator_01` / CREATOR | 首次政策、个人 workspace、九区 Profile 保存/发布 ACTIVE；自身邀请详情、接受/拒绝/撤回、邀请历史；暂停与恢复画像 | 不见他人邀请/评分/私密底线；缺必需字段不得发布；拒绝无强制理由且不成为接受；终态按钮禁用 | PARTIAL，原项目：真实登录；21 小时修改保存 v6、发布 v7；CREATED 邀请未提前出现（服务端验证 0 项）；发布后刷新 SERVICE_UNAVAILABLE，保留旧列表，详情与响应未通过 |
| `demand_owner_01` / DEMAND_OWNER | 十三区 Demand 新建/保存/提交、整改再提交、版本比较；自己的 Trust 举报与申诉；取消独立测试需求 | 不审核自己的 Demand；未确认资金不得进入合格匹配；当前页失效后不伪造空列表；已取消/过期对象不允许继续业务 | PARTIAL：核心需求 FUNDED v15；三个不可变版本；NEEDS_CHANGES / VERIFIED / DISCREPANCY 历史及 `/scope` 差异重读 |
| `operations_reviewer_01` / OPERATIONS_REVIEWER | 最小审核队列领取、记录 `/scope` 整改、第二次领取、验证通过、本人完成历史 | 不代 Owner 修改内容；释放不等于最终决定；stale ETag 显式报错并重读 | PARTIAL：本人四条完成历史重读 |
| `finance_operator_01` / FINANCE_OPERATOR | 领取 VERIFIED Demand，读取不可变需求版本、预算和零资金证据；四项声明后首份确认 | 单人确认不 FUNDED；计划预算不显示为余额；provider/payment 始终 NONE | PARTIAL：本人双人确认历史重读 |
| `finance_operator_02` / FINANCE_OPERATOR | 读取最新审查并独立确认第二席；Demand FUNDED；历史与终态可重读 | 不复用首人的会话/确认；实际金额仍为零，法律效果 NO_REAL_FUNDS_OR_PAYMENT | PARTIAL：本人双人确认历史重读 |
| `org_admin_01` / ORG_ADMIN | 组织名称/成员/邀请；向固定合成账号邀请 DEMAND_OWNER，接受后查看成员；暂停/恢复/撤销成员资格；撤销未接受邀请 | 自己与最后管理员操作禁用；链接 token 仅 fragment 且首次读取清除；个人 workspace 保留 | PARTIAL：真实登录及职责确认；名称 Updated、成员 4、邀请 5 含 ACCEPTED / REVOKED；本人暂停/撤销禁用 |
| `access_admin_01` / ACCESS_ADMIN | 精确十账号；非 self 暂停/恢复、撤销全部会话；临时 duty 授予/读取/撤销 | 自身按钮禁用；详情无邮箱/OIDC subject；恢复不复活旧 cookie；其它账号不见账号管理 | PARTIAL：真实登录及职责确认；预置十账号列表；点开 Creator 读取 current v6，仅有 CREATOR，其余职责未授予 |
| `trust_officer_01` / TRUST_OFFICER | 领取 Owner 举报、分诊草稿、公布措施/结论、本人完成历史 | 未领取前不披露案件详情；不能执行自己的独立高风险解除复核；原决定不替代申诉复核 | PARTIAL：本人一条完成案件重读；当前队列为空 |
| `trust_officer_02` / TRUST_OFFICER | 独立领取高风险解除复核，按实际分配完成解除；fresh 读取结果 | 不因同一平台职责获得另一人当前案件；双人要求不能被同人第二次操作满足 | PARTIAL：真实登录及 TRUST_OFFICER 确认；本人完成 0、活动 0、高风险复核 0；未写入 |
| `appeal_reviewer_01` / APPEAL_REVIEWER | 领取 Owner 申诉，读取不可变原决定、保存复核草稿、发布决定、本人完成历史 | 复核必须独立；申请人与复核者字段分开；读失败不显示空队列 | PARTIAL：真实登录；完成 1，点击 VACATE_AND_REMAND 后 fresh 终态读取成功，显示 PROCEDURAL_ERROR → VACATE_AND_REMAND 和结构化评估；受限正文不在 DOM |
| Owner 的 Candidate Selector 分配 | Matching 工作台选择需求、领取分配、读取当前 attempt；只见已接受安全卡片；人工选择到服务端终态或显式不选择关闭 | 不披露评分/排名/Creator 内部 ID；尚未接受不能选择；OPEN/PENDING_CHOICE 不当作 SELECTED；跨 run/stale 不可选择 | NOT RUN |
| Operations 的 Matching Reviewer 分配 | 领取下一项；领取后才显示 exact run、eligible 候选/评分；配置 1–672 小时邀请、创建和发布；刷新/释放 | 领取前无全局候选清单；空/小数/超界时长禁用创建；重复邀请禁用；异常 attempt 仅服务端允许时可失效 | PARTIAL：已读取空队列；领取及后续邀请未验 |

Matching Selection 的终态读取权限绑定原始有效 Session。exact-ID 补充读取支持同一 Session
刷新和服务重启后的终态重读；即使用户相同，重新登录取得的新 Session 也不延续这份对象权限，
应返回 404。该限制来自现有 RLS 与 IAM marker，不能把重新登录后的 404 当作需要放宽的历史读取缺陷。
这一边界是代码和 HTTP 回归判据，尚未宣称浏览器实际复验通过。

## 贯穿协作的浏览器执行顺序

1. 十账号分别登录，核对 workspace 与入口；逐份读取合成政策的法律效果，再完成合成政策确认。
2. Creator 发布与匹配条件一致的 Profile；Owner 提交 Demand。
3. Operations 要求整改，Owner 修正再提交，Operations 重新领取并验证。
4. 两名 Finance 分别确认，验证第二席之后才 FUNDED；每次写后刷新重读。
5. Matching runtime 完成后由 Operations 领取匹配审核、创建/发布邀请；Creator 读取冻结披露并接受；
   Owner 领取 Selector 分配后人工选择。必须观察最终服务端终态。
6. 用独立测试 Demand/attempt 检查 Creator 拒绝、撤回及 Owner 不选择关闭；不能毁掉主路径证据。
7. 完成 Owner → Trust officer 1 → Trust officer 2 / Appeal reviewer 的独立协作；Owner 读回结果。
8. 管理动作最后执行：邀请/成员生命周期、账号暂停/恢复、会话撤销和临时职责变更；验证旧页失效。
9. 刷新、退出再登录及 Docker 正常 stop/resume 后，从各角色浏览器重读其权限允许的相同事实与
   历史；Matching Selection 另用原有效 Session 重读，并确认新 Session 不继承对象权限。

以上为未完整执行的浏览器计划，不能据此将任一环境未覆盖的动作标为通过。
每笔浏览器写入均记录操作前后可见状态及对象短标识；并发冲突使用双标签页，依赖故障由独立、
明确的本机测试步骤触发。不得通过页面脚本调用隐藏 API 来冒充点按旅程。

## 桌面与移动验收判据

- 十账号首页、任务面板、角色主要工作台均有实际截图/可访问树证据，能找到下一步并返回。
- 390px 和 320px 窄屏无页面级横向溢出、遮住主按钮、被 sticky 区域盖住的字段或不可达滚动区域。
- 长中文、UUID/摘要、多人列表和候选卡片可换行；输入与 select 不超出卡片，状态不只靠颜色区分。
- 键盘可到达主操作、列表、取消/重试和退出；Tab 顺序和可见焦点合理；控件名称与屏幕文字对应。
- 空数据必须已由服务端验证；读取失败保留旧快照与错误提示。写结果未知时只允许同请求恢复，
  不允许切换 workspace 或执行相邻写入；明确 412 后显示重读/冲突解决。
- 首次政策、同意拒绝、step-up、退出、会话撤销和重新登录均真实跨页面完成，不能只确认 SSR 文本。
- 浏览器控制台无本轮造成的未处理异常、React hydration 错误或失效资源；浏览器运行时无真实第三方通知。
- 测完恢复临时 viewport；保留的页面不展示一次性邀请 token、cookie 或其他认证材料。

指定页面与区域已有视觉证据：原项目 Creator 1440px、Access Admin 1280px，以及修复后的
Access Admin 390px / 320px 页头；新项目 Creator 邀请页 390×844、320×844。原页头刷新/退出按钮
未被账号信息覆盖，320px 标签分两行、账号与会话号正常省略；新邀请页及 sticky header 无横向溢出。
尚未对所有角色页面、焦点、触摸和滚动逐项完成以上判据。

## 现有自动化能够证明什么

以下是对测试实现的只读分类，未在本记录中声称重新运行通过。

| 测试类别与代表文件 | 实际执行机制 | 可以支持的结论 | 不能支持的结论 |
| --- | --- | --- | --- |
| `matching-ui.test.mjs`、`product-shell.test.mjs`、`org-admin-ui.test.mjs`、`appeal-ui.test.mjs` | 读取 TSX/CSS/route 源码并正则匹配 | 必要代码/文字/role gating/恢复分支存在；禁止模式未出现在该源码范围 | React 真正渲染、点击成功、正确网络时序、视觉排版、完整角色协作 |
| `session-manager-ui.test.mjs`、`editor-conflict-merge-ui.test.mjs` | 混合源码检查与部分纯函数调用；响应式项检查 CSS 字符串 | 指定 helper 的状态转换、恢复绑定和 CSS 声明存在 | 实际窄屏尺寸、焦点/触摸行为、可访问性辅助技术体验 |
| `matching-contract.test.mjs`、`app-contract.test.mjs`、`trust-contract.test.mjs`、`appeal-contract.test.mjs` | 真实 parser/intent/proxy helper；以 fixture 或 mock 请求/响应测试 | 闭合 DTO、字段/长度约束、路径/头部约束、错误映射、请求绑定 | 真实数据库授权、生产 BFF 配置、OIDC cookie、实际 worker/coordinator 推进 |
| `workbench-refresh.test.mjs`、`appeal-reviewer-snapshot.test.mjs`、编辑器 merge/diff 测试 | 执行纯函数、受控 Promise/状态协调 | 测试输入下旧响应不覆盖新快照、失败不部分提交、冲突合并规则 | 组件 effect/卸载与真实网络是否按同一顺序调用；按钮是否可用 |
| `trust-ui.test.mjs`、`organization-invitation-time.test.mjs` | 源码检查加 Node 子进程/时区函数测试 | 日期转换在列出的时区场景正确 | 浏览器本地 datetime 控件输入/显示与交互 |
| `rendered-shell.test.mjs` | 导入已构建 worker 并调用 `worker.fetch`，检查 SSR HTML/headers | 初始页面和 join scrub 顺序、CSP nonce、缺 backend 失败关闭 | 浏览器解析执行 CSP、client hydration、首屏后登录/角色 UI、真实画面 |
| HTTPS 十账号 runner 与 PostgreSQL gate | 真实接口及数据库事实（由主验收另行保存） | 覆盖到的业务/权限/持久化与原子性 | 桌面/移动视觉 QA 或用户通过网页完成该动作 |

## 已解决的浏览器入口问题

初期子任务的浏览器清单为空、创建 IAB 或 Chrome 失败，只能证明该子任务未获得浏览器通道。
主任务后来取得 IAB `id=1`，最初访问出现 `ERR_CONNECTION_CLOSED`；没有越过 URL policy
读取其 `data:` 错误页。主任务随后打开 Docker 文档 HTTP 入口，完成 loopback 连通性检查。

用户亲自添加 hosts 映射后，错误进入 `ERR_CERT_AUTHORITY_INVALID` 阶段；用户再亲自信任本次
精确叶证书后，主任务已经正常访问两个 HTTPS origin 并完成登录。未安装根 CA，未改变代理，
未改用非 CUA 浏览器自动化。这些早期入口错误应保留为历史，不再作为当前验收阻断。

本次保留了证书 SAN、Caddy hostname、OIDC callback 和 Secure cookie 的精确域名关系。
Chrome helper 的独立 profile、域名映射与叶证书 SPKI 允许项仍是另一人工入口，不能据此推断
IAB 的行为。此前 curl 返回 200 仅说明指定解析和 CA 条件下 edge 可访问，不是浏览器 QA。

## 未系统覆盖的 UI 范围与自动化证据

- 原环境十账号登录和工作台读取已完成；第二个 `-fixed` 项目已有 Creator 登录，Matching 列表、
  SENT v2 与 ACCEPTED v3 详情实际读取及指定窄屏证据。当前 `-verified` 项目已有 Creator fresh 登录、
  三条邀请列表、三条终态详情及同 Session 跨重启读取，最终 1280px 桌面截图正常；不能移用前两项目记录。
- 尚未系统检查其余移动页面的主按钮、焦点、遮挡、触摸与滚动；指定页面的截图和 DOM 无水平溢出
  结果不能覆盖所有角色页面。
- Matching4 已修复 ingest 变量歧义并通过 19 项静态/真实 PostgreSQL 回归；Matching5 已修复
  coordinator 领取后的 RLS scope 与首次审计版本，通过 20 项静态/真实 PG 回归，含 SYSTEM_CLOSE
  实际 NO_MATCH 与 CHOOSE/CLOSE 领取/重放。最终四分支 HTTP 另见当前 `-verified` 结果，不扩大为浏览器点按。
- 审核领取 503 的直接原因是封闭 ID 用途缺少 Matching 名称；有限补齐后的 SecureRuntimeSources
  桥接回归 19 项通过。Matching6 另外修复 CLAIM 下 result 可见性与 attempt/run 行锁；最终真实 PG
  与静态回归 22 项通过并已正式迁移。这两个问题不能合并归因为 RLS，也不能用桥接回归宣称
  数据库链路通过。
- 随后的真实 HTTP CREATE 首次 201、重放 409 暴露 prepare 先于 receipt 的顺序问题；Matching7
  安全回执 probe 的真实 PG/静态 22 项回归和 Python 桥接 15 项回归已通过。原项目后续发布与重放
  均为 200；回执恢复继续要求当前有效分配，不能绕过权限。
- 原邀请发布后，Creator 读取因已冻结披露的时间格式不符合 v1 契约而返回 503。Matching8 已修正
  未来快照生成并严格拒绝不合契约的创建；原项目停止保留，不修改原邀请、快照、摘要或旧证据。
  当前 `-verified` 已完成四分支验收，但不能把新数据通过写成旧坏邀请已修复。
- Matching8 静态与真实 PostgreSQL 回归 23 项通过，含实际创建/发布后 Creator list/detail 与原 HTTP
  闭合投影及摘要校验；严格 Z 时间及相关领域/桥接 43 项通过，候选部署门禁 251 项与只读 verifier
  通过。这些均不是新环境浏览器点按证据。
- 第二个 `-fixed` 环境 CHOOSE 的 Trust 时间参考点修复已部署并成功推进；随后 `complete_selection_v1` SQL
  返回 P0002，Matching9 前向修复已过独立 PG 回归。最终原 job 为 FAILED / LEASE_EXHAUSTED，attempt_count 3，
  HTTP 选择仍 PENDING_CHOICE、数据库 selection/attempt 为 OPEN。Creator ACCEPTED 读取
  不等于该项目的 Selection 已完成，不能宣称其选择终态通过；Matching1–8 不改写。
- 失败 OPEN attempt 会占据后续审核队列，当前没有恢复该失败 job 的合法 redrive 入口；已转到
  新干净 `-verified` 环境完成验收，`-fixed` 停止并保留证据。迁移修复不等于旧任务已恢复，不能将
  新环境结果回写为先前未完成的 Matching 浏览器旅程通过。
- Matching9 的 24 项静态/真实 PG 回归已完成选择与关闭终态、原 Session 终态读取和回执/权限负向；
  v28 的 251 项部署测试与只读 verifier 已通过。以上结果不是 `-verified` 环境的浏览器证据。
- 当前 `-verified` 的四分支真实 HTTP 已报告通过：选择到 MATCHED、拒绝/撤回后关闭到 NO_MATCH、
  零候选到 NO_MATCH；人工分支原 Session 终态读取成功。独立数据库 4×18 项检查与 Matching
  重启 HTTP 与数据库前后对照已通过；当前项目实际 UI 另列，不将 HTTP 成功当作浏览器点按通过。
- `editor-result.json` 已有真实 HTTP `EDITOR_CONCURRENCY_PRIVACY_E2E_GREEN`：覆盖精确重放、
  payload 冲突 409、旧版本 412、三方数据保留、显式合并、不可变版本、未分配需求/私密画像隐藏，
  以及独立测试需求取消。该结果不是上述动作的浏览器点按证据。
- SYSTEM workflow 9 项、Matching HTTP 26 项、本机 wrapper 9 项、独立凭据 prepare 9 项聚焦
  回归通过；本机真实 provision 正常。分组可能重叠，不相加，也不替代 Matching 的最终业务终态。

完整的 Docker、HTTP 与 PostgreSQL 验收记录见
[本机 Docker 工作流程验收](docker-workflow-acceptance-2026-09-04.md)。
