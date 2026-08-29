# 愿作内部试运行工作台

这是 `INTERNAL_SANDBOX` 的受邀账号工作台。首页使用真实 Session/IAM 投影和 `/v1/app` 编辑器契约；旧的 `/v1/local/*` 代理仍只为 `local_synthetic` 回归验收保留，不再驱动首页。

工作台当前提供：

- OIDC 签出/登录入口，以及 `/v1/auth/session`、`/v1/me` 的服务端账号投影；
- `GET /v1/me/sessions` 的“我的会话”安全摘要、刷新与游标翻页；当前会话可退出，其他 ACTIVE 会话可按 IAM38 精确撤销，并以账号、bootstrap 会话、目标、CSRF 和原幂等键恢复结果未知的请求；
- `GET /v1/app/workspaces` 的受控职责范围发现、单候选自动选择和多候选切换；
- CREATOR 的画像列表、详情、九分区结构化草稿编辑与发布；
- DEMAND_OWNER 的需求列表、详情、十三分区结构化草稿编辑与提交；
- 日期、金额、枚举、布尔值、稳定条目 ID 与可增删列表，不要求操作者手写 JSON；
- 保存前检查日期、预算、里程碑总计、AI/数据边界和跨分区领域/技能关系；
- OPERATIONS_REVIEWER 的审核队列、领取、fresh detail、按冲突或工作量原因释放误领分配、结构化整改和验证；
- FINANCE_OPERATOR 的零资金合成复核与双人独立确认，以及 ACCESS_ADMIN、ORG_ADMIN 的账号和组织管理；
- TRUST_OFFICER 的报告、案件、保护措施与裁决，以及同一 Demand Owner 登录会话内从 eligible outcome 到 Appeal 的显式、安全交接；
- 每对象 ETag/`If-Match`、每写入幂等键、412 三方冲突处理；
- 仅当前标签页的草稿恢复，以及写入结果未知时对原请求的原样重试。

浏览器不会下发或推断角色。创建入口只由当前所选工作区返回的关闭 `role_codes` 控制，绝不使用 `/v1/me` 的跨层聚合角色；对象操作由 `/v1/app` 返回的 `capabilities` 控制。

## 前置条件

- Node.js `>=22.13.0`；用 `node --version` 检查。
- npm 必须按本目录的 `package-lock.json` 执行 `npm ci`。
- 平台 API 已真实提供以下同源上游接口：
  - `GET /v1/auth/session`
  - `POST /v1/auth/oidc/authorizations`
  - `GET /v1/auth/oidc/callback`
  - `GET /v1/me`
  - `GET /v1/me/sessions`
  - `GET /v1/app/workspaces`
  - `/v1/app/profiles*`
  - `/v1/app/demands*`
- 本机开发时，平台 API 只监听精确 loopback，例如 `127.0.0.1:8000`。

如果真实 API composition 尚未 ready，首页会按设计显示 `FAIL CLOSED`；不要添加浏览器假数据 fallback，也不要把这个状态描述成可操作平台。

## 本机开发

先启动已完成 production composition 的平台 API，再在另一个终端执行：

```bash
cd web
cp .env.example .env.local
npm ci
npm run dev
```

访问 `http://127.0.0.1:3000`。`DESIRE_LOOPBACK_BASE_URL` 只接受带明确端口的 `http://127.0.0.1:<port>`、`http://[::1]:<port>`，或容器内部唯一值 `http://api:8000`；它拒绝任意域名、凭据、子路径、查询和重定向。

在容器部署组合完成后，应优先按根目录运行手册启动全栈，并从 edge 的唯一入口访问，不要把 Web 开发端口作为服务器入口。

## 安全边界

同源 BFF 对三组路由分别使用关闭 allowlist：`/v1/auth/*`、精确的 `/v1/me` 与 `/v1/me/sessions`、`/v1/app/*` 和遗留的 `/v1/local/*`。它不信任浏览器提交的 `Origin`、`Host`、`Forwarded` 或 `X-Forwarded-*`，只从已校验的平台 base URL 重建上游 `Origin`。

Cookie、CSRF、ETag、幂等键和少量关闭请求头可按 allowlist 转发；后端仍必须验证 Session、CSRF、角色、组织、对象能力、revision 和 idempotency。工作区发现只允许无 `X-Workspace-Id` 的精确 `GET`；所有其他 `/v1/app` 请求必须携带从发现结果中选择的 `X-Workspace-Id`。OIDC callback 只允许关闭参数集合，并且只接受 API 返回的同源相对 `303 Location`。

审核详情中的“释放当前审核分配”不是审核决定。浏览器只允许 `CONFLICT_DECLARED` 与 `WORKLOAD_RELEASE` 两个原因，并绑定当前 ETag、CSRF 与独立幂等键；成功响应必须仍是 `SUBMITTED`、携带新 ETag 且 `review_assignment = null`。冲突释放后本人不会再次看到或领取同一 submission/version，工作量释放仍可重新领取；浏览器不在本地猜测队列结果，而是刷新服务端投影。

所选工作区 ID、草稿和未确认写入仅进入当前标签页的 `sessionStorage`；工作区切换会清空选中对象、集合与未确认写入，再按新工作区重载。草稿和未确认写入 24 小时后失效。“我的会话”的列表/游标以及 Trust→Appeal 交接只存在组件内存中，并绑定当前 Session/Workspace；切换、重新 bootstrap、退出或刷新都会清除。不使用 `localStorage`、IndexedDB 或浏览器角色缓存。

## 验证

```bash
npm run build
npm run typecheck
npm run lint
node --test tests/*.test.mjs
```

也可以运行 `npm test`；它会先构建，再执行关闭契约、代理边界、静态产品壳和服务端渲染测试。

## Gate 与发布边界

此软件可用于受邀内部账号和合成资料的操作演练，但不改变 Gate 结论：

- `G1 NO-GO`：不得开展真人研究；
- `G2 NO-GO`：不得接入真实合同、资金或支付。

本目录没有 OpenAI Sites 配置或发布命令。不要将其发布到 OpenAI Sites。
