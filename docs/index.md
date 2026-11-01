# 愿作文档

愿作（Desire Supply）帮助个人和小团队发现值得解决的问题，掌握从构想到实际使用的创造过程，并获得可持续收入、成果权利和社会联系。

**首先阅读[《愿作整体方案报告：让人重新掌握完整创造》](/desire-supply-platform-design.md)。** 这是理解项目定位、平台机制、现有差距、推进路线与合作资源需求的主入口。

讨论是否值得投入、谁会付款以及为什么愿意参与，请读[商业可行性与利益相关方选择分析](/foundations/commercial-feasibility-and-stakeholder-choices.md)：逐项比较现有替代方式，核算买方、创作者和平台的利益，并提出降低合作阻力的服务与试点调整。

## 我们正在建设什么

方案以作品与长期实践为中心，连接三种来源：**委托、创作者发起、共同或公共创造**。平台既帮助人找到合适的有偿合作，也帮助人提出问题、塑造成果、连接使用者、持续改进，并保留自己的权利和选择。AI 提高生产能力，是这一方向的条件；收入、权利与社会关系仍需要产品和制度共同支持。

## 如何理解当前状态

| 层次 | 当前事实 | 阅读时的边界 |
| --- | --- | --- |
| 已实现的内部工作台 | `platform/` + `web/` 已有受邀账号、画像与需求编辑、审核、合成资金确认、匹配邀请与选择，以及限定范围的信任安全与申诉 | 固定为 `INTERNAL_SANDBOX`；不等于已开放真人业务 |
| 已实现的本地运营工具 | `mvp/` 提供匿名资料校验、预算检查、可解释匹配、决策留痕与批次报告 | CLI 是独立路径，不代表当前平台的全部 |
| 合成制度原型 | `demo/` 演练协议、交付、付款、成果反馈、申诉和数据权 | 状态可重置，不能据此宣布真实工作台已经闭环 |
| 新的整体方案 | 作品与长期实践、三种创造来源、持续使用反馈、成果权利、可持续支持与共同治理 | 属于重新规划的建设方向，需验证并逐步实现 |

当前 Web 的协议、交付验收与结算尚未接入完整流程，真实资金和完整产品持续经营也未上线。真人研究、真实合同和资金试点须遵守现有[启动决策边界](/foundations/readiness-and-start-decision.md)；新的方案不改变这些事实。

## 按目的阅读

- **了解项目或考虑提供协助**：先读[整体方案报告](/desire-supply-platform-design.md)，再读[项目介绍](/guide/introduction.md)和[核心概念](/guide/core-concepts.md)。
- **理解制度与使命**：阅读[社会契约](/foundations/social-contract.md)、[经济宪法](/foundations/economic-constitution.md)与[使命衡量和学习](/foundations/mission-measurement-and-learning-plan.md)。
- **检查当前实现或开展技术合作**：从[系统总览](/architecture/overview.md)、[内部试运行平台](/architecture/internal-pilot-platform.md)和[项目结构](/development/project-structure.md)进入；现有架构文档中的目标模型不自动代表已接入功能。
- **运行内部合成演练**：使用[本机 Docker 指南](/operations/docker-local.md)和[运行与逐步检查](/operations/run-and-check.md)；CLI 路径见[快速开始](/guide/quick-start.md)。
- **准备试点与运营**：结合[产品与试点定义](/foundations/product-and-pilot-definition.md)、[研究计划](/foundations/research-and-evidence-plan.md)和[首批项目流程](/operations/pilot.md)，先核对适用阶段与授权条件。

> 本入口更新于 2026-11-01。主报告表达整体方向；技术与运营文档保留各自阶段、适用范围和证据状态。实现事实以当前代码、已接入路径及相应验证记录为准。
