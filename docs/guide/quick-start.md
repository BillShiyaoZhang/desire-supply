# 快速开始

本页帮助开发者在本机跑通一条完整的虚构数据链路。示例数据不包含真实参与者信息。

## 环境要求

- Python 3.9 或更高版本；
- [`uv`](https://docs.astral.sh/uv/)；
- Git；
- 可选：Node.js，仅在使用 `docsify-cli` 预览文档时需要。

MVP 没有第三方运行时依赖；`uv` 主要负责创建隔离环境和运行命令。

## 跑通 MVP

从仓库根目录执行：

```bash
cd mvp
uv run mvp init
uv run mvp import creator samples/creators.json
uv run mvp import demand samples/demands.json
uv run mvp validate demand demand-demo-001
uv run mvp budget demand-demo-001
uv run mvp match demand-demo-001 --top 3
uv run mvp explain demand-demo-001 creator-demo-001
uv run mvp decision demand-demo-001 \
  --selected creator-demo-001 \
  --invited creator-demo-001 creator-demo-002 \
  --responses samples/responses.json \
  --reason ALGORITHM_TOP
uv run mvp outcome project-demo-001 --file samples/outcome.json
uv run mvp report pilot-demo
```

运行后会出现 `mvp/local-data/mvp.sqlite3`，批次报告位于 `mvp/local-data/reports/pilot-demo/`。`local-data/` 除 `.gitkeep` 外已被 Git 忽略。

如果希望完全隔离演示数据，把全局参数放在子命令前：

```bash
uv run mvp --data-dir /tmp/desire-supply-demo init
```

## 运行测试

```bash
cd mvp
uv run python -m unittest discover -s tests -v
```

测试覆盖资料门槛、预算边界、硬过滤、排序确定性、隐私泄漏防护、快照和批次报告。测试通过只说明软件规则按预期执行，不代表业务假设已经被市场验证。

## 预览文档站

无需安装依赖的方式：

```bash
python3 -m http.server 5174 --directory docs
```

打开 `http://localhost:5174`。如果需要 Docsify 的文件监听能力：

```bash
cd docs
npm install
npm run dev
```

提交文档前运行：

```bash
python3 scripts/verify_docs.py
```

## 开始真实项目前

不要把示例运行等同于可以处理真实资料。至少还需完成以下工作：

1. 确定单一适用地区以及合同、税务、支付和争议责任；
2. 选择受控的联系人存储、签署、付款、沟通和文件工具；
3. 完成资料备份恢复、删除和事件响应演练；
4. 按同意模板向每位参与者解释用途、可见性、保存期限和退出方式；
5. 使用匿名随机 ID，把身份信息与匹配数据隔离；
6. 逐项执行仓库中的 `mvp/operations/launch-checklist.md`。

真实运行的完整顺序见[首批项目流程](/operations/pilot.md)。
