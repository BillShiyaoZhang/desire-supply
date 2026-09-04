# 愿作（Desire Supply）

愿作帮助拥有 AI 增强生产力的个人，找到自己愿意投入、能够做好、且能获得合理报酬的真实劳动机会。

当前仓库同时保留两条明确分开的运行路径：

- `platform/` + `web/`：面向内部试运行的多角色工作台，包含受邀 OIDC 账号、安全会话摘要、服务端工作区与职责发现、结构化 Profile/Demand 编辑、审核、双人资金确认、账号/组织管理、Trust 与 Appeal；
- `mvp/`：单运营者使用的礼宾式命令行工具，继续负责匿名化资料校验、预算检查、可解释匹配、决策留痕与批次报告。

多角色工作台当前仍固定为 `INTERNAL_SANDBOX`：只允许预置的虚构合成账号与合成资料，不能据此处理真人资料、真实合同、真实资金或公开注册。这个边界不会把已经实现的账号平台说成不存在，也不会把内部沙箱说成生产系统。

## 从这里开始

- [本机全部使用 Docker](./docs/operations/docker-local.md)：一条命令启动工作台，初始化、开发工具链和文档预览都在容器中完成
- [管理员查看需求全流程](./docs/operations/admin-demand-timeline.md)：按需求查看各阶段进度、参与人员、操作时间线及尚未接入的环节
- [Current-head v30 静态模式头](./docs/operations/current-head-v30.md)：IAM48 / Profile5 / Demand16 / Trust24 / Matching11 / Taxonomy2 的数据库合同与恢复边界
- [Current-head v27 静态模式头](./docs/operations/current-head-v27.md)：IAM46 / Profile5 / Demand15 / Trust22 / Matching3 / Taxonomy2 的只读静态发布与恢复边界；`STATIC VERIFIED / NOT PRODUCTION EXECUTED`
- [Current-head v26 静态模式头](./docs/operations/current-head-v26.md)：冻结历史，只保留 IAM43 / Profile3 / Demand13 / Trust19 / Taxonomy2 的原始静态事实
- [Current-head v25 历史静态模式头](./docs/operations/current-head-v25.md)：冻结的 IAM42 / Profile3 / Demand12 / Trust18 / Taxonomy2 隐私安全 HTTP telemetry 与有界容器日志发布边界
- [Current-head v24 历史静态模式头](./docs/operations/current-head-v24.md)：冻结的 IAM42 / Profile3 / Demand12 / Trust18 / Taxonomy2 历史发布边界
- [Current-head v23 历史静态模式头](./docs/operations/current-head-v23.md)：冻结的 IAM42 / Profile3 / Demand12 / Trust17 / Taxonomy2 历史发布边界
- [多角色工作台运行与检查](./docs/operations/run-and-check.md)：十账号、八职责、首次登录、核心旅程与恢复检查
- [Docker 部署](./docs/operations/container-deployment.md)：合成内部沙箱的完整容器组合与验证边界
- [Dev Container](./docs/development/dev-container.md)：一致的开发工具链与数据库环境
- [Web 工作台说明](./web/README.md)：角色能力、浏览器安全边界与本机开发
- [MVP 使用说明](./mvp/README.md)：礼宾式命令行工具的安装、演示和日常命令
- [完整文档](https://billshiyaozhang.github.io/desire-supply/)与[文档源文件](./docs/index.md)：项目设计、运行手册和演进边界

公开注册、真实支付、聊天和社区功能仍不属于当前内部沙箱。真实试点必须另外通过仓库定义的研究、法律、数据和资金门禁。

## 文档站本地预览

```bash
./scripts/docker-local.sh up
./scripts/docker-local.sh docs
```

打开 `http://localhost:5174`。已有 Python 环境时也可使用 `python3 -m http.server 5174 --directory docs`。
提交文档前运行 `python3 scripts/verify_docs.py` 检查导航与站内链接，或在开发容器中执行该命令。
