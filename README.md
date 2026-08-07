# 愿作（Desire Supply）

愿作帮助拥有 AI 增强生产力的个人，找到自己愿意投入、能够做好、且能获得合理报酬的真实劳动机会。

当前阶段采用邀请制的**礼宾式 MVP**：发起人亲自访谈和协调，参与者继续使用熟悉的沟通、合同、支付与文件工具；本仓库只提供匿名化资料校验、预算检查、可解释匹配、决策留痕与验证报告。

## 从这里开始

- [完整文档](https://billshiyaozhang.github.io/desire-supply/)：项目介绍、快速开始、系统架构、领域模型、安全设计与演进路线
- [文档源文件](./docs/index.md)：适合在仓库中阅读
- [MVP 使用说明](./mvp/README.md)：安装、演示和日常命令
- [MVP 启动清单](./mvp/operations/launch-checklist.md)：首个真实项目前必须完成的事项
- [人工运营手册](./mvp/operations/pilot-runbook.md)：从招募到复盘的标准流程

公开平台、账户、支付、聊天和社区功能不属于首轮 MVP。首轮以 5 个进入付费阶段的真实项目为一个验证批次。

## 文档站本地预览

```bash
python3 -m http.server 5174 --directory docs
```

打开 `http://localhost:5174`。提交文档前运行 `python3 scripts/verify_docs.py` 检查导航与站内链接。
