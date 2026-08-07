# 项目结构

## 仓库地图

```text
desire-supply/
├── .github/workflows/
│   └── deploy-docs.yml        # 校验并发布 docs/ 到 GitHub Pages
├── docs/                      # Docsify 文档站与系统设计
│   ├── architecture/          # 当前与目标架构
│   ├── development/           # 开发、测试、演进
│   ├── guide/                 # 新手入口
│   ├── operations/            # 运营概览
│   ├── reference/             # CLI、配置、发布参考
│   ├── index.html             # Docsify 静态入口
│   ├── _sidebar.md            # 全站导航
│   └── *.md                   # 原始平台/MVP设计决策
├── mvp/
│   ├── config/                # 冻结且版本化的业务规则
│   ├── operations/            # 真实批次运行手册与安全流程
│   ├── samples/               # 可提交的虚构 JSON
│   ├── src/desire_mvp/        # Python 应用实现
│   ├── templates/             # 11 份访谈、协议和复盘模板
│   ├── tests/                 # unittest 行为测试
│   ├── local-data/            # Git 忽略的 SQLite 与报告
│   └── pyproject.toml
├── scripts/
│   └── verify_docs.py         # 文档导航和站内链接检查
├── idea.md                    # 最初问题陈述
└── README.md                  # 仓库入口
```

## 代码分层

### 接口层

`mvp/src/desire_mvp/cli.py` 是唯一应用接口，负责：解析参数、选择用例、组织错误、决定输出格式。它可以调用领域函数和仓库，但不应内嵌新的匹配公式或 SQL。

`__main__.py` 只把 `python -m desire_mvp` 转交给 `cli.main`；`pyproject.toml` 的 `mvp` console script 指向同一入口。

### 领域规则层

`validation.py`、`budget.py`、`matching.py`、`explanations.py`、`decisions.py` 和 `privacy.py` 承担业务规则。函数优先接收普通字典和显式配置，不在内部读取全局数据库或环境变量，使规则可以独立测试和复算。

### 数据与投影层

`repository.py` 是 SQLite 的唯一访问边界；业务模块不直接执行 SQL。`reports.py` 从 Repository 读取事实并构建批次读模型。`models.py` 的数据类用于明确函数结果，不承担持久化 ORM 职责。

### 配置层

`mvp/config/manifest.json` 决定当前活动文件。四个版本文件分别表达词表、匹配、预算和原因代码。配置不是随意参数，而是影响参与者机会的业务策略，变更需要证据、版本和测试。

## 文档与实现的关系

| 文档 | 主要事实来源 |
| --- | --- |
| 当前 MVP 架构 | `mvp/src/desire_mvp/` 与 tests |
| 领域模型 | `repository.py`、samples、数据字典 |
| 匹配与预算 | `matching.py`、`budget.py`、config |
| 数据安全 | `privacy.py`、资料保护手册、实际运营控制 |
| CLI 参考 | `cli.build_parser()` |
| 目标平台架构 | 设计决策；尚无实现 |

修改接口、配置、状态、不变量或目录时，应在同一变更中更新对应文档。`scripts/verify_docs.py` 只能发现结构问题，不能发现语义过期。

## 新功能应放在哪里

- 新的资料门槛：`validation.py`，并补充样例和验证测试；
- 新的不可协商边界：`matching.filter_candidate`、版本配置、原因说明和测试；
- 新的排序信号：先通过批次证据，再修改 `matching.py` 和新版本配置；
- 新的 CLI 用例：在独立领域函数/Repository 方法完成规则后，由 `cli.py` 编排；
- 新的存储查询：只加入 Repository；报告聚合保持只读；
- 新的真实运营动作：先更新 `mvp/operations` 和模板，不默认写成软件；
- 长期平台想法：记录在目标设计或演进路线，不混入当前实现说明。

## 依赖原则

当前工具刻意保持零第三方运行时依赖。引入依赖前需要说明：标准库为什么不足、供应链与维护成本、许可、离线可用性、数据是否离开本机，以及如何测试和锁定版本。文档站使用固定版本 CDN 资源，但不承载任何真实项目数据。
